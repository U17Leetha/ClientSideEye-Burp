document.addEventListener("DOMContentLoaded", async () => {
  const tokenInput = document.getElementById("bridgeToken");
  const status = document.getElementById("status");
  const stored = await chrome.storage.local.get([
    window.ClientSideEyeBridge.TOKEN_STORAGE_KEY,
  ]);
  tokenInput.value = stored[window.ClientSideEyeBridge.TOKEN_STORAGE_KEY] || "";
  if (!tokenInput.value) {
    status.textContent =
      "Set the bridge token shown in the Burp ClientSideEye tab.";
  }
});

document.getElementById("saveToken").addEventListener("click", async () => {
  const tokenInput = document.getElementById("bridgeToken");
  const status = document.getElementById("status");
  const token = (tokenInput.value || "").trim();
  await chrome.storage.local.set({
    [window.ClientSideEyeBridge.TOKEN_STORAGE_KEY]: token,
  });
  status.textContent = token ? "Bridge token saved." : "Bridge token cleared.";
});

document.getElementById("scanSend").addEventListener("click", async () => {
  await runScan(document.getElementById("scanSend"), false);
});

document.getElementById("watchSend").addEventListener("click", async () => {
  await runScan(document.getElementById("watchSend"), true);
});

async function runScan(button, watchMode) {
  const status = document.getElementById("status");
  const token = await window.ClientSideEyeBridge.getBridgeToken();
  button.disabled = true;
  status.textContent = watchMode
    ? "Watching current tab for DOM changes..."
    : "Scanning current tab...";

  if (!token) {
    status.textContent = "Set the bridge token before sending findings.";
    button.disabled = false;
    return;
  }

  let tab;
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) {
      status.textContent = "No active tab.";
      return;
    }

    status.textContent = watchMode
      ? "Watching current tab...\nInstalling runtime hooks..."
      : "Scanning current tab...\nInstalling runtime hooks...";
    await window.ClientSideEyeRuntime.ensureRuntimeHooks(tab.id);

    status.textContent = "Scanning current tab...\nProbing bridge...";
    const activeBridge = await window.ClientSideEyeBridge.resolveBridgeBase(token);
    if (!activeBridge) {
      status.textContent =
        "Bridge not reachable on localhost ports 17373-17382.";
      return;
    }

    const findingUrl = `${activeBridge}/api/finding`;
    let firstError = "";
    let nonOkStatus = "";
    let ok = 0;
    let failed = 0;
    const findings = watchMode
      ? await window.ClientSideEyeFindings.collectWatchedFindings(tab.id, status)
      : await window.ClientSideEyeFindings.collectSnapshotFindings(tab.id);
    if (findings.length === 0) {
      status.textContent = watchMode
        ? "No new actionable controls found during watch window."
        : "No disabled/hidden actionable controls found.";
      return;
    }

    for (const finding of findings) {
      const body = new URLSearchParams({
        source: "clientsideeye-browser-bridge",
        url: finding.url || tab.url || "",
        type: finding.type || "HIDDEN_OR_DISABLED_CONTROL",
        severity: finding.severity || "MEDIUM",
        confidence: String(finding.confidence ?? 55),
        title: finding.title || "Client-side gated control found in browser DOM",
        summary:
          finding.summary ||
          "Control appears client-side disabled/hidden in rendered DOM and may still be triggerable.",
        evidence: finding.evidence || "(no evidence)",
        identity: finding.identity || "",
        recommendation:
          "Do not rely on client-side disable/hide state for authorization. Enforce server-side authorization for action endpoints.",
      });

      try {
        const response = await window.ClientSideEyeBridge.fetchWithTimeout(
          findingUrl,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              "X-ClientSideEye-Token": token,
            },
            body,
          },
          1200,
        );
        if (response.ok) {
          ok += 1;
        } else {
          failed += 1;
          if (!nonOkStatus) {
            nonOkStatus = `${response.status} ${response.statusText}`;
          }
          if (response.status === 401) {
            nonOkStatus = "401 Unauthorized (check bridge token)";
          }
        }
      } catch (error) {
        failed += 1;
        if (!firstError) {
          firstError = String(error?.message || error);
        }
      }
    }

    status.textContent =
      `Bridge: ${activeBridge}\nFound: ${findings.length}\nSent: ${ok}\nFailed: ${failed}` +
      (nonOkStatus ? `\nHTTP error: ${nonOkStatus}` : "") +
      (firstError ? `\nFirst error: ${firstError}` : "");
  } catch (error) {
    status.textContent = `Error: ${error?.message || error}`;
  } finally {
    try {
      if (tab?.id) {
        await window.ClientSideEyeRuntime.removeRuntimeHooks(tab.id);
      }
    } catch (error) {}
    button.disabled = false;
  }
}
