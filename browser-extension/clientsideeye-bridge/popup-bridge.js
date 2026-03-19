window.ClientSideEyeBridge = (() => {
  const BRIDGE_PORTS = [
    17373, 17374, 17375, 17376, 17377, 17378, 17379, 17380, 17381, 17382,
  ];
  const FETCH_TIMEOUT_MS = 1200;
  const TOKEN_STORAGE_KEY = "clientsideeye_bridge_token";

  let bridgeBase = null;

  async function getBridgeToken() {
    const tokenInput = document.getElementById("bridgeToken");
    const raw = (tokenInput?.value || "").trim();
    if (raw) {
      return raw;
    }
    const stored = await chrome.storage.local.get([TOKEN_STORAGE_KEY]);
    return (stored[TOKEN_STORAGE_KEY] || "").trim();
  }

  async function resolveBridgeBase(token) {
    if (bridgeBase) {
      return bridgeBase;
    }
    let lastError = "";
    for (const port of BRIDGE_PORTS) {
      const base = `http://127.0.0.1:${port}`;
      try {
        const response = await fetchWithTimeout(
          `${base}/api/health`,
          {
            method: "GET",
            headers: token ? { "X-ClientSideEye-Token": token } : {},
          },
          FETCH_TIMEOUT_MS,
        );
        if (response.ok) {
          bridgeBase = base;
          return bridgeBase;
        }
        lastError = `${base} -> ${response.status} ${response.statusText}`;
      } catch (error) {
        lastError = `${base} -> ${String(error?.message || error)}`;
      }
    }
    if (lastError) {
      const status = document.getElementById("status");
      if (status) {
        status.textContent = `Bridge probe failed.\nLast: ${lastError}`;
      }
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

  return {
    TOKEN_STORAGE_KEY,
    getBridgeToken,
    resolveBridgeBase,
    withTimeout,
    fetchWithTimeout,
  };
})();
