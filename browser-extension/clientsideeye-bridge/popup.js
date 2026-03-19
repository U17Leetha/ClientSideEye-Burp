const BRIDGE_PORTS = [
  17373, 17374, 17375, 17376, 17377, 17378, 17379, 17380, 17381, 17382,
];
let bridgeBase = null;
const EXEC_TIMEOUT_MS = 5000;
const FETCH_TIMEOUT_MS = 1200;
const TOKEN_STORAGE_KEY = "clientsideeye_bridge_token";
const WATCH_DURATION_MS = 15000;
const WATCH_INTERVAL_MS = 2000;

document.addEventListener("DOMContentLoaded", async () => {
  const tokenInput = document.getElementById("bridgeToken");
  const status = document.getElementById("status");
  const stored = await chrome.storage.local.get([TOKEN_STORAGE_KEY]);
  tokenInput.value = stored[TOKEN_STORAGE_KEY] || "";
  if (!tokenInput.value) {
    status.textContent =
      "Set the bridge token shown in the Burp ClientSideEye tab.";
  }
});

document.getElementById("saveToken").addEventListener("click", async () => {
  const tokenInput = document.getElementById("bridgeToken");
  const status = document.getElementById("status");
  const token = (tokenInput.value || "").trim();
  await chrome.storage.local.set({ [TOKEN_STORAGE_KEY]: token });
  status.textContent = token ? "Bridge token saved." : "Bridge token cleared.";
});

document.getElementById("scanSend").addEventListener("click", async () => {
  const btn = document.getElementById("scanSend");
  await runScan(btn, false);
});

document.getElementById("watchSend").addEventListener("click", async () => {
  const btn = document.getElementById("watchSend");
  await runScan(btn, true);
});

async function runScan(btn, watchMode) {
  const status = document.getElementById("status");
  const token = await getBridgeToken();
  btn.disabled = true;
  status.textContent = watchMode
    ? "Watching current tab for DOM changes..."
    : "Scanning current tab...";

  if (!token) {
    status.textContent = "Set the bridge token before sending findings.";
    btn.disabled = false;
    return;
  }

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

    status.textContent = watchMode
      ? "Watching current tab...\nInstalling runtime hooks..."
      : "Scanning current tab...\nInstalling runtime hooks...";
    await ensureRuntimeHooks(tab.id);

    status.textContent = "Scanning current tab...\nProbing bridge...";
    const activeBridge = await resolveBridgeBase(token);
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
    const findings = watchMode
      ? await collectWatchedFindings(tab.id, status)
      : await collectSnapshotFindings(tab.id);
    if (findings.length === 0) {
      status.textContent = watchMode
        ? "No new actionable controls found during watch window."
        : "No disabled/hidden actionable controls found.";
      btn.disabled = false;
      return;
    }

    for (const f of findings) {
      const body = new URLSearchParams({
        source: "clientsideeye-browser-bridge",
        url: f.url || tab.url || "",
        type: f.type || "HIDDEN_OR_DISABLED_CONTROL",
        severity: f.severity || "MEDIUM",
        confidence: String(f.confidence ?? 55),
        title: f.title || "Client-side gated control found in browser DOM",
        summary:
          f.summary ||
          "Control appears client-side disabled/hidden in rendered DOM and may still be triggerable.",
        evidence: f.evidence || "(no evidence)",
        identity: f.identity || "",
        recommendation:
          "Do not rely on client-side disable/hide state for authorization. Enforce server-side authorization for action endpoints.",
      });

      try {
        const r = await fetchWithTimeout(
          findingUrl,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              "X-ClientSideEye-Token": token,
            },
            body,
          },
          FETCH_TIMEOUT_MS,
        );
        if (r.ok) {
          ok++;
        } else {
          failed++;
          if (!nonOkStatus) nonOkStatus = `${r.status} ${r.statusText}`;
          if (r.status === 401) {
            nonOkStatus = "401 Unauthorized (check bridge token)";
          }
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
}

async function ensureRuntimeHooks(tabId) {
  await withTimeout(
    chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      func: installRuntimeHooks,
    }),
    EXEC_TIMEOUT_MS,
    "Timed out installing runtime hooks in tab",
  );
}

async function collectSnapshotFindings(tabId) {
  const [{ result }] = await withTimeout(
    chrome.scripting.executeScript({
      target: { tabId },
      func: collectFindings,
    }),
    EXEC_TIMEOUT_MS,
    "Timed out executing scanner in tab",
  );
  return Array.isArray(result) ? result : [];
}

function installRuntimeHooks() {
  const root = document.documentElement;
  if (!root) return { installed: false };

  const state = window.__clientsideeyeRuntime || {
    installed: false,
    entries: [],
    seq: 0,
  };
  window.__clientsideeyeRuntime = state;

  const persist = () => {
    try {
      root.dataset.clientsideeyeRuntime = JSON.stringify(state.entries.slice(-200));
      root.dataset.clientsideeyeRuntimeUpdated = String(Date.now());
    } catch (e) {}
  };

  const summarizeHeaders = (headersLike) => {
    const out = [];
    const add = (name) => {
      const normalized = String(name || '').trim().toLowerCase();
      if (!normalized) return;
      if (!out.includes(normalized)) out.push(normalized);
    };
    try {
      if (!headersLike) return out;
      if (typeof headersLike.forEach === 'function') {
        headersLike.forEach((_, key) => add(key));
      } else if (Array.isArray(headersLike)) {
        headersLike.forEach((item) => add(Array.isArray(item) ? item[0] : item && item.name));
      } else if (typeof headersLike === 'object') {
        Object.keys(headersLike).forEach(add);
      }
    } catch (e) {}
    return out;
  };

  const extractGraphqlOperation = (url, body) => {
    const bodyText = String(body || '');
    const urlText = String(url || '');
    const candidate = `${urlText} ${bodyText}`;
    if (!/graphql|\bquery\b|\bmutation\b|\bsubscription\b/i.test(candidate)) return '';

    try {
      const parsed = JSON.parse(bodyText);
      if (parsed && typeof parsed === 'object') {
        if (typeof parsed.operationName === 'string' && parsed.operationName.trim()) {
          return parsed.operationName.trim();
        }
        if (typeof parsed.query === 'string') {
          const match = parsed.query.match(/\b(?:query|mutation|subscription)\s+([A-Za-z0-9_]+)/);
          if (match) return match[1];
        }
      }
    } catch (e) {}

    const bodyMatch = bodyText.match(/\b(?:query|mutation|subscription)\s+([A-Za-z0-9_]+)/);
    if (bodyMatch) return bodyMatch[1];

    try {
      const parsedUrl = new URL(urlText, location.href);
      const op = parsedUrl.searchParams.get('operationName');
      if (op) return op;
      const query = parsedUrl.searchParams.get('query') || '';
      const queryMatch = query.match(/\b(?:query|mutation|subscription)\s+([A-Za-z0-9_]+)/);
      if (queryMatch) return queryMatch[1];
    } catch (e) {}

    return 'anonymous';
  };

  const record = (kind, url, extra = {}) => {
    try {
      const normalizedUrl = String(url || '').slice(0, 500);
      if (!normalizedUrl) return;
      const headerNames = summarizeHeaders(extra.headers);
      const body = String(extra.body || '').slice(0, 240);
      const graphqlOp = extractGraphqlOperation(normalizedUrl, body);
      state.seq += 1;
      state.entries.push({
        id: state.seq,
        kind,
        url: normalizedUrl,
        method: String(extra.method || '').slice(0, 32),
        body,
        initiator: String(extra.initiator || '').slice(0, 80),
        headerNames,
        hasAuthHeader: headerNames.some((name) => /authorization|x-api-key|api-key|token|cookie/i.test(name)),
        graphqlOp,
        ts: Date.now(),
      });
      if (state.entries.length > 200) {
        state.entries.splice(0, state.entries.length - 200);
      }
      persist();
    } catch (e) {}
  };

  if (!state.installed) {
    state.installed = true;

    try {
      const origFetch = window.fetch;
      if (typeof origFetch === 'function') {
        window.fetch = function(input, init) {
          try {
            const req = input instanceof Request ? input : null;
            const url = req ? req.url : input;
            const method = (init && init.method) || (req && req.method) || 'GET';
            const headers = (init && init.headers) || (req && req.headers) || null;
            const body = (init && init.body) || '';
            record('fetch', url, { method, body, headers, initiator: 'fetch' });
          } catch (e) {}
          return origFetch.apply(this, arguments);
        };
      }
    } catch (e) {}

    try {
      const origOpen = XMLHttpRequest.prototype.open;
      const origSend = XMLHttpRequest.prototype.send;
      const origSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
      XMLHttpRequest.prototype.open = function(method, url) {
        try {
          this.__clientsideeyeMethod = method;
          this.__clientsideeyeUrl = url;
          this.__clientsideeyeHeaders = [];
        } catch (e) {}
        return origOpen.apply(this, arguments);
      };
      XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
        try {
          this.__clientsideeyeHeaders = this.__clientsideeyeHeaders || [];
          this.__clientsideeyeHeaders.push([name, value]);
        } catch (e) {}
        return origSetRequestHeader.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function(body) {
        try {
          record('xmlhttprequest', this.__clientsideeyeUrl, {
            method: this.__clientsideeyeMethod || 'GET',
            body,
            headers: this.__clientsideeyeHeaders || [],
            initiator: 'xmlhttprequest',
          });
        } catch (e) {}
        return origSend.apply(this, arguments);
      };
    } catch (e) {}

    try {
      const OrigWebSocket = window.WebSocket;
      if (typeof OrigWebSocket === 'function') {
        window.WebSocket = function(url, protocols) {
          try { record('websocket', url, { initiator: 'websocket' }); } catch (e) {}
          return protocols === undefined ? new OrigWebSocket(url) : new OrigWebSocket(url, protocols);
        };
        window.WebSocket.prototype = OrigWebSocket.prototype;
      }
    } catch (e) {}

    try {
      const OrigEventSource = window.EventSource;
      if (typeof OrigEventSource === 'function') {
        window.EventSource = function(url, config) {
          try { record('eventsource', url, { initiator: 'eventsource' }); } catch (e) {}
          return config === undefined ? new OrigEventSource(url) : new OrigEventSource(url, config);
        };
        window.EventSource.prototype = OrigEventSource.prototype;
      }
    } catch (e) {}
  }

  persist();
  return { installed: true, entries: state.entries.length };
}

async function collectWatchedFindings(tabId, statusEl) {
  const seen = new Set();
  const aggregated = [];
  const startedAt = Date.now();
  while (Date.now() - startedAt < WATCH_DURATION_MS) {
    const findings = await collectSnapshotFindings(tabId);
    for (const finding of findings) {
      const key =
        finding.identity ||
        `${finding.url || ""}|${finding.evidence || ""}|${finding.title || ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      aggregated.push(finding);
    }
    const secondsLeft = Math.max(
      0,
      Math.ceil((WATCH_DURATION_MS - (Date.now() - startedAt)) / 1000),
    );
    if (statusEl) {
      statusEl.textContent = `Watching current tab...\nUnique findings: ${aggregated.length}\nTime left: ${secondsLeft}s`;
    }
    if (secondsLeft <= 0) break;
    await new Promise((resolve) => setTimeout(resolve, WATCH_INTERVAL_MS));
  }
  return aggregated;
}

async function resolveBridgeBase(token) {
  if (bridgeBase) return bridgeBase;
  let lastErr = "";
  for (const port of BRIDGE_PORTS) {
    const base = `http://127.0.0.1:${port}`;
    try {
      const r = await fetchWithTimeout(
        `${base}/api/health`,
        {
          method: "GET",
          headers: token
            ? {
                "X-ClientSideEye-Token": token,
              }
            : {},
        },
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

async function getBridgeToken() {
  const tokenInput = document.getElementById("bridgeToken");
  const raw = (tokenInput?.value || "").trim();
  if (raw) return raw;
  const stored = await chrome.storage.local.get([TOKEN_STORAGE_KEY]);
  return (stored[TOKEN_STORAGE_KEY] || "").trim();
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
  const tokenWords =
    /(token|jwt|bearer|auth|session|secret|api[_-]?key|refresh)/i;
  const endpointWords = /(\/api\/|\/graphql\b|\/admin\b|\/internal\b)/i;
  const dangerousSinkWords =
    /\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|Function|setTimeout\s*\(|setInterval\s*\()/i;
  const interestingInitiators =
    /^(fetch|xmlhttprequest|script|iframe|link|beacon)$/i;
  const graphqlWords = /\b(query|mutation|subscription)\b/i;

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
  const seen = new Set();

  const pushFinding = (finding) => {
    const identity =
      finding.identity ||
      `${finding.type || ""}|${finding.url || location.href}|${finding.evidence || finding.title || ""}`;
    if (seen.has(identity)) return;
    seen.add(identity);
    out.push({ ...finding, identity });
  };

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
    const identity = [
      (el.tagName || "").toLowerCase(),
      el.id || "",
      el.getAttribute("data-testid") || "",
      el.getAttribute("name") || "",
      el.getAttribute("href") || "",
      text.slice(0, 80),
    ].join("|");

    let conf = 45;
    if (disabled) conf += 15;
    if (hidden) conf += 10;
    if (actionable(el)) conf += 10;
    if (riskWords.test(`${attrs} ${text}`)) conf += 15;
    if (conf > 100) conf = 100;

    const sev = conf >= 85 ? "HIGH" : conf >= 60 ? "MEDIUM" : "LOW";
    pushFinding({
      url: location.href,
      type: "HIDDEN_OR_DISABLED_CONTROL",
      severity: sev,
      confidence: conf,
      title: "Client-side disabled/hidden control found in rendered DOM",
      summary: `Detected an actionable element that is ${disabled && hidden ? "disabled and hidden" : disabled ? "disabled" : "hidden"} on the client side.`,
      evidence: outer || `${attrs} text="${text}"`,
      identity,
    });
  }

  try {
    for (const storageName of ["localStorage", "sessionStorage"]) {
      const store = window[storageName];
      if (!store) continue;
      for (let i = 0; i < store.length; i++) {
        const key = store.key(i) || "";
        const value = store.getItem(key) || "";
        if (!tokenWords.test(`${key} ${value}`)) continue;
        const trimmedValue =
          value.length > 120 ? `${value.slice(0, 120)}...` : value;
        pushFinding({
          url: location.href,
          type: "STORAGE_TOKEN",
          severity: value.length > 20 ? "MEDIUM" : "LOW",
          confidence: value.length > 20 ? 75 : 58,
          title: `Potential token or secret in ${storageName}`,
          summary: `${storageName} contains a key/value pair that looks authentication- or secret-related.`,
          evidence: `${storageName}[${JSON.stringify(key)}] = ${trimmedValue}`,
          identity: `${storageName}|${key}`,
        });
      }
    }
  } catch (e) {}

  const scriptNodes = Array.from(document.scripts || []);
  for (const script of scriptNodes) {
    const src = script.src || "";
    const body = (script.textContent || "").trim();

    if (src && endpointWords.test(src)) {
      pushFinding({
        url: location.href,
        type: "JAVASCRIPT_ENDPOINT_REFERENCE",
        severity: /\/admin\b|\/internal\b/i.test(src) ? "MEDIUM" : "INFO",
        confidence: /\/graphql\b|\/api\//i.test(src) ? 78 : 60,
        title: "Script or endpoint reference found in runtime DOM",
        summary:
          "The rendered page references a script or endpoint path that may expose additional functionality.",
        evidence: src,
        identity: `script-src|${src}`,
      });
    }

    if (!body) continue;

    if (dangerousSinkWords.test(body)) {
      const match = body.match(dangerousSinkWords);
      pushFinding({
        url: location.href,
        type: "DOM_XSS_SINK",
        severity: /\beval\b|\bFunction\b/.test(match?.[0] || "")
          ? "MEDIUM"
          : "LOW",
        confidence: /\beval\b|\bFunction\b/.test(match?.[0] || "") ? 72 : 58,
        title: "Potential DOM XSS sink found in runtime script",
        summary:
          "Inline runtime script contains a dangerous DOM or code-execution sink worth manual review.",
        evidence: (match?.[0] || body).slice(0, 220),
        identity: `sink|${match?.[0] || body.slice(0, 80)}`,
      });
    }

    if (
      /addEventListener\s*\(\s*['"]message['"]|onmessage\s*=|postMessage\s*\(/i.test(
        body,
      )
    ) {
      const checksOrigin = /event\.origin|targetOrigin|\.origin/i.test(body);
      pushFinding({
        url: location.href,
        type: "POSTMESSAGE_HANDLER",
        severity: checksOrigin ? "INFO" : "MEDIUM",
        confidence: checksOrigin ? 55 : 74,
        title: "postMessage usage found in runtime script",
        summary: checksOrigin
          ? "Inline runtime script uses postMessage/message handlers and appears to reference origin checks."
          : "Inline runtime script uses postMessage/message handlers without obvious origin validation nearby.",
        evidence: body.replace(/\s+/g, " ").slice(0, 220),
        identity: `postmessage|${body.slice(0, 80)}`,
      });
    }

    const endpointMatches = body.match(
      /(?:fetch|axios\.(?:get|post|put|delete|patch)|xhr\.open)\s*\(?\s*['"]([^'"]{2,200})['"]/gi,
    );
    if (endpointMatches) {
      for (const match of endpointMatches.slice(0, 10)) {
        pushFinding({
          url: location.href,
          type: "JAVASCRIPT_ENDPOINT_REFERENCE",
          severity: /\/admin\b|\/internal\b/i.test(match) ? "MEDIUM" : "INFO",
          confidence: /\/graphql\b|\/api\//i.test(match) ? 80 : 66,
          title: "Endpoint reference found in runtime script",
          summary:
            "Runtime script contains a likely client-side endpoint or route reference.",
          evidence: match.replace(/\s+/g, " ").slice(0, 220),
          identity: `runtime-endpoint|${match}`,
        });
      }
    }
  }

  try {
    const runtimeEntries = JSON.parse(
      document.documentElement?.dataset?.clientsideeyeRuntime || "[]",
    );
    for (const entry of runtimeEntries) {
      const url = String(entry?.url || "");
      const kind = String(entry?.kind || entry?.initiator || "runtime");
      const method = String(entry?.method || "").toUpperCase();
      const body = String(entry?.body || "");
      if (!url) continue;
      const lower = url.toLowerCase();
      const isGraphql = /\/graphql\b/.test(lower) || graphqlWords.test(body);
      const isInteresting =
        endpointWords.test(lower) ||
        /^(fetch|xmlhttprequest|websocket|eventsource)$/i.test(kind) ||
        isGraphql;
      if (!isInteresting) continue;

      const title = isGraphql
        ? "Runtime GraphQL activity observed in browser"
        : kind === "websocket"
          ? "Runtime WebSocket endpoint observed in browser"
          : kind === "eventsource"
            ? "Runtime EventSource endpoint observed in browser"
            : "Runtime network endpoint observed in browser";
      const evidence = `${method || kind} -> ${url}${body ? ` | body: ${body.slice(0, 120)}` : ""}`;
      pushFinding({
        url: location.href,
        type: "RUNTIME_NETWORK_REFERENCE",
        severity:
          /\/admin\b|\/internal\b/.test(lower) ||
          isGraphql ||
          kind === "websocket"
            ? "MEDIUM"
            : "INFO",
        confidence: isGraphql ? 90 : entry.hasAuthHeader ? 86 : kind === "fetch" || kind === "xmlhttprequest" ? 82 : 74,
        title,
        summary: `The page context reported ${kind} activity during runtime instrumentation.`,
        evidence: `${evidence.slice(0, 260)}${entry.headerNames?.length ? ` | headers: ${entry.headerNames.join(',')}` : ""}${entry.graphqlOp ? ` | graphql: ${entry.graphqlOp}` : ""}${entry.hasAuthHeader ? " | auth-header" : ""}`.slice(0, 320),
        identity: `runtime-hook|${kind}|${method}|${url}|${body.slice(0, 40)}`,
      });
    }
  } catch (e) {}

  try {
    const resources = performance.getEntriesByType("resource") || [];
    for (const entry of resources) {
      const name = entry?.name || "";
      const initiatorType = (entry?.initiatorType || "").toLowerCase();
      if (!name) continue;
      if (
        !interestingInitiators.test(initiatorType) &&
        !endpointWords.test(name)
      )
        continue;

      const lower = name.toLowerCase();
      const isGraphql = /\/graphql\b/.test(lower);
      const isApiLike =
        /\/api\/|\/admin\b|\/internal\b|graphql/.test(lower) ||
        initiatorType === "fetch" ||
        initiatorType === "xmlhttprequest";
      if (!isApiLike) continue;

      pushFinding({
        url: location.href,
        type: "RUNTIME_NETWORK_REFERENCE",
        severity:
          /\/admin\b|\/internal\b/.test(lower) || isGraphql ? "MEDIUM" : "INFO",
        confidence: isGraphql ? 82 : initiatorType === "fetch" ? 76 : 68,
        title: "Runtime network endpoint observed in browser",
        summary: `The browser observed a ${initiatorType || "resource"} request/reference during page execution.`,
        evidence: `${initiatorType || "resource"} -> ${name}`,
        identity: `runtime-network|${initiatorType}|${name}`,
      });
    }
  } catch (e) {}

  return out.slice(0, 120);
}
