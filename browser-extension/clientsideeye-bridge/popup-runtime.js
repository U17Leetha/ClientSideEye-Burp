window.ClientSideEyeRuntime = (() => {
  const EXEC_TIMEOUT_MS = 5000;

  async function ensureRuntimeHooks(tabId) {
    await window.ClientSideEyeBridge.withTimeout(
      chrome.scripting.executeScript({
        target: { tabId },
        world: "MAIN",
        func: installRuntimeHooks,
      }),
      EXEC_TIMEOUT_MS,
      "Timed out installing runtime hooks in tab",
    );
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
        root.dataset.clientsideeyeRuntime = JSON.stringify(
          state.entries.slice(-200),
        );
        root.dataset.clientsideeyeRuntimeUpdated = String(Date.now());
      } catch (error) {}
    };

    const summarizeHeaders = (headersLike) => {
      const out = [];
      const add = (name) => {
        const normalized = String(name || "").trim().toLowerCase();
        if (!normalized || out.includes(normalized)) {
          return;
        }
        out.push(normalized);
      };
      try {
        if (!headersLike) {
          return out;
        }
        if (typeof headersLike.forEach === "function") {
          headersLike.forEach((_, key) => add(key));
        } else if (Array.isArray(headersLike)) {
          headersLike.forEach((item) =>
            add(Array.isArray(item) ? item[0] : item && item.name),
          );
        } else if (typeof headersLike === "object") {
          Object.keys(headersLike).forEach(add);
        }
      } catch (error) {}
      return out;
    };

    const extractGraphqlOperation = (url, body) => {
      const bodyText = String(body || "");
      const urlText = String(url || "");
      const candidate = `${urlText} ${bodyText}`;
      if (!/graphql|\bquery\b|\bmutation\b|\bsubscription\b/i.test(candidate)) {
        return "";
      }

      try {
        const parsed = JSON.parse(bodyText);
        if (parsed && typeof parsed === "object") {
          if (typeof parsed.operationName === "string" && parsed.operationName.trim()) {
            return parsed.operationName.trim();
          }
          if (typeof parsed.query === "string") {
            const match = parsed.query.match(
              /\b(?:query|mutation|subscription)\s+([A-Za-z0-9_]+)/,
            );
            if (match) {
              return match[1];
            }
          }
        }
      } catch (error) {}

      const bodyMatch = bodyText.match(
        /\b(?:query|mutation|subscription)\s+([A-Za-z0-9_]+)/,
      );
      if (bodyMatch) {
        return bodyMatch[1];
      }

      try {
        const parsedUrl = new URL(urlText, location.href);
        const operationName = parsedUrl.searchParams.get("operationName");
        if (operationName) {
          return operationName;
        }
        const query = parsedUrl.searchParams.get("query") || "";
        const queryMatch = query.match(
          /\b(?:query|mutation|subscription)\s+([A-Za-z0-9_]+)/,
        );
        if (queryMatch) {
          return queryMatch[1];
        }
      } catch (error) {}

      return "anonymous";
    };

    const record = (kind, url, extra = {}) => {
      try {
        const normalizedUrl = String(url || "").slice(0, 500);
        if (!normalizedUrl) {
          return;
        }
        const headerNames = summarizeHeaders(extra.headers);
        const body = String(extra.body || "").slice(0, 240);
        const graphqlOp = extractGraphqlOperation(normalizedUrl, body);
        state.seq += 1;
        state.entries.push({
          id: state.seq,
          kind,
          url: normalizedUrl,
          method: String(extra.method || "").slice(0, 32),
          body,
          initiator: String(extra.initiator || "").slice(0, 80),
          headerNames,
          hasAuthHeader: headerNames.some((name) =>
            /authorization|x-api-key|api-key|token|cookie/i.test(name),
          ),
          graphqlOp,
          ts: Date.now(),
        });
        if (state.entries.length > 200) {
          state.entries.splice(0, state.entries.length - 200);
        }
        persist();
      } catch (error) {}
    };

    if (!state.installed) {
      state.installed = true;

      try {
        const originalFetch = window.fetch;
        if (typeof originalFetch === "function") {
          window.fetch = function(input, init) {
            try {
              const request = input instanceof Request ? input : null;
              const url = request ? request.url : input;
              const method = (init && init.method) || (request && request.method) || "GET";
              const headers = (init && init.headers) || (request && request.headers) || null;
              const body = (init && init.body) || "";
              record("fetch", url, { method, body, headers, initiator: "fetch" });
            } catch (error) {}
            return originalFetch.apply(this, arguments);
          };
        }
      } catch (error) {}

      try {
        const originalOpen = XMLHttpRequest.prototype.open;
        const originalSend = XMLHttpRequest.prototype.send;
        const originalSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
        XMLHttpRequest.prototype.open = function(method, url) {
          try {
            this.__clientsideeyeMethod = method;
            this.__clientsideeyeUrl = url;
            this.__clientsideeyeHeaders = [];
          } catch (error) {}
          return originalOpen.apply(this, arguments);
        };
        XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
          try {
            this.__clientsideeyeHeaders = this.__clientsideeyeHeaders || [];
            this.__clientsideeyeHeaders.push([name, value]);
          } catch (error) {}
          return originalSetRequestHeader.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function(body) {
          try {
            record("xmlhttprequest", this.__clientsideeyeUrl, {
              method: this.__clientsideeyeMethod || "GET",
              body,
              headers: this.__clientsideeyeHeaders || [],
              initiator: "xmlhttprequest",
            });
          } catch (error) {}
          return originalSend.apply(this, arguments);
        };
      } catch (error) {}

      try {
        const OriginalWebSocket = window.WebSocket;
        if (typeof OriginalWebSocket === "function") {
          window.WebSocket = function(url, protocols) {
            try {
              record("websocket", url, { initiator: "websocket" });
            } catch (error) {}
            return protocols === undefined
              ? new OriginalWebSocket(url)
              : new OriginalWebSocket(url, protocols);
          };
          window.WebSocket.prototype = OriginalWebSocket.prototype;
        }
      } catch (error) {}

      try {
        const OriginalEventSource = window.EventSource;
        if (typeof OriginalEventSource === "function") {
          window.EventSource = function(url, config) {
            try {
              record("eventsource", url, { initiator: "eventsource" });
            } catch (error) {}
            return config === undefined
              ? new OriginalEventSource(url)
              : new OriginalEventSource(url, config);
          };
          window.EventSource.prototype = OriginalEventSource.prototype;
        }
      } catch (error) {}
    }

    persist();
    return { installed: true, entries: state.entries.length };
  }

  return {
    EXEC_TIMEOUT_MS,
    ensureRuntimeHooks,
  };
})();
