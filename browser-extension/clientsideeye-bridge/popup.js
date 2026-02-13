const BRIDGE_PORTS = [
  17373, 17374, 17375, 17376, 17377, 17378, 17379, 17380, 17381, 17382,
];
let bridgeBase = null;
const EXEC_TIMEOUT_MS = 5000;
const FETCH_TIMEOUT_MS = 1200;

document.getElementById("scanSend").addEventListener("click", async () => {
  const btn = document.getElementById("scanSend");
  const status = document.getElementById("status");
  btn.disabled = true;
  status.textContent = "Scanning current tab...";

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (!tab?.id) {
      status.textContent = "No active tab.";
      btn.disabled = false;
      return;
    }

    status.textContent = "Scanning current tab...\nInjecting scanner...";
    const [{ result }] = await withTimeout(
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: collectFindings,
      }),
      EXEC_TIMEOUT_MS,
      "Timed out executing scanner in tab",
    );

    const findings = Array.isArray(result) ? result : [];
    if (findings.length === 0) {
      status.textContent = "No disabled/hidden actionable controls found.";
      btn.disabled = false;
      return;
    }

    status.textContent = "Scanning current tab...\nProbing bridge...";
    const activeBridge = await resolveBridgeBase();
    if (!activeBridge) {
      status.textContent =
        "Bridge not reachable on localhost ports 17373-17382.";
      btn.disabled = false;
      return;
    }

    const findingUrl = `${activeBridge}/api/finding`;
    let firstError = "";
    let nonOkStatus = "";
    let ok = 0;
    let failed = 0;
    for (const f of findings) {
      const body = new URLSearchParams({
        source: "clientsideeye-browser-bridge",
        url: f.url || tab.url || "",
        type: "HIDDEN_OR_DISABLED_CONTROL",
        severity: f.severity || "MEDIUM",
        confidence: String(f.confidence ?? 55),
        title: f.title || "Client-side gated control found in browser DOM",
        summary:
          f.summary ||
          "Control appears client-side disabled/hidden in rendered DOM and may still be triggerable.",
        evidence: f.evidence || "(no evidence)",
        recommendation:
          "Do not rely on client-side disable/hide state for authorization. Enforce server-side authorization for action endpoints.",
      });

      try {
        const r = await fetchWithTimeout(
          findingUrl,
          {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body,
          },
          FETCH_TIMEOUT_MS,
        );
        if (r.ok) {
          ok++;
        } else {
          failed++;
          if (!nonOkStatus) nonOkStatus = `${r.status} ${r.statusText}`;
        }
      } catch (e) {
        failed++;
        if (!firstError) firstError = String(e?.message || e);
      }
    }

    status.textContent =
      `Bridge: ${activeBridge}\nFound: ${findings.length}\nSent: ${ok}\nFailed: ${failed}` +
      (nonOkStatus ? `\nHTTP error: ${nonOkStatus}` : "") +
      (firstError ? `\nFirst error: ${firstError}` : "");
  } catch (e) {
    status.textContent = `Error: ${e?.message || e}`;
  } finally {
    btn.disabled = false;
  }
});

async function resolveBridgeBase() {
  if (bridgeBase) return bridgeBase;
  let lastErr = "";
  for (const port of BRIDGE_PORTS) {
    const base = `http://127.0.0.1:${port}`;
    try {
      const r = await fetchWithTimeout(
        `${base}/api/health`,
        { method: "GET" },
        FETCH_TIMEOUT_MS,
      );
      if (r.ok) {
        bridgeBase = base;
        return bridgeBase;
      }
      lastErr = `${base} -> ${r.status} ${r.statusText}`;
    } catch (e) {
      lastErr = `${base} -> ${String(e?.message || e)}`;
    }
  }
  if (lastErr) {
    const status = document.getElementById("status");
    if (status) status.textContent = `Bridge probe failed.\nLast: ${lastErr}`;
  }
  return null;
}

function withTimeout(promise, ms, message) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(message)), ms),
    ),
  ]);
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...(options || {}), signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function collectFindings() {
  const riskWords =
    /(save|submit|delete|remove|admin|role|permission|approve|reject|reset|unlock|disable|enable|export|import|grant|revoke|token|key)/i;

  const isDisabled = (el) => {
    if (!el) return false;
    const cls = (el.className || "").toString();
    return (
      !!el.disabled ||
      el.getAttribute("aria-disabled") === "true" ||
      /\b(disabled|pf-m-disabled|is-disabled|btn-disabled)\b/i.test(cls)
    );
  };

  const isHidden = (el) => {
    if (!el) return false;
    const cs = window.getComputedStyle(el);
    return (
      !!el.hidden ||
      cs.display === "none" ||
      cs.visibility === "hidden" ||
      cs.opacity === "0"
    );
  };

  const actionable = (el) => {
    if (!el) return false;
    const tag = (el.tagName || "").toLowerCase();
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (tag === "button") return true;
    if (tag === "a" || tag === "select" || tag === "textarea" || tag === "form")
      return true;
    if (tag === "input")
      return ["", "submit", "button", "image", "reset", "password"].includes(
        type,
      );
    if (el.getAttribute("role") === "button") return true;
    return !!el.getAttribute("onclick") || !!el.getAttribute("formaction");
  };

  const nodes = Array.from(
    document.querySelectorAll(
      "button,a,input,select,textarea,form,div,span,[role='button']",
    ),
  );
  const out = [];

  for (const el of nodes) {
    if (!actionable(el)) continue;
    const disabled = isDisabled(el);
    const hidden = isHidden(el);
    if (!disabled && !hidden) continue;

    const attrs = [
      "id",
      "name",
      "type",
      "data-testid",
      "class",
      "aria-disabled",
      "href",
      "title",
      "aria-label",
    ]
      .map((k) => `${k}="${el.getAttribute(k) || ""}"`)
      .join(" ");
    const text = (el.innerText || el.textContent || el.value || "")
      .replace(/\s+/g, " ")
      .trim();
    const outer = (el.outerHTML || "").replace(/\s+/g, " ").slice(0, 420);

    let conf = 45;
    if (disabled) conf += 15;
    if (hidden) conf += 10;
    if (actionable(el)) conf += 10;
    if (riskWords.test(`${attrs} ${text}`)) conf += 15;
    if (conf > 100) conf = 100;

    const sev = conf >= 85 ? "HIGH" : conf >= 60 ? "MEDIUM" : "LOW";
    out.push({
      url: location.href,
      severity: sev,
      confidence: conf,
      title: "Client-side disabled/hidden control found in rendered DOM",
      summary: `Detected an actionable element that is ${disabled && hidden ? "disabled and hidden" : disabled ? "disabled" : "hidden"} on the client side.`,
      evidence: outer || `${attrs} text="${text}"`,
    });
  }

  return out.slice(0, 50);
}
