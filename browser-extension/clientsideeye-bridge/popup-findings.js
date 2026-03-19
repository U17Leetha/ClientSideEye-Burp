window.ClientSideEyeFindings = (() => {
  const WATCH_DURATION_MS = 15000;
  const WATCH_INTERVAL_MS = 2000;

  async function collectSnapshotFindings(tabId) {
    const [{ result }] = await window.ClientSideEyeBridge.withTimeout(
      chrome.scripting.executeScript({
        target: { tabId },
        func: collectFindings,
      }),
      window.ClientSideEyeRuntime.EXEC_TIMEOUT_MS,
      "Timed out executing scanner in tab",
    );
    return Array.isArray(result) ? result : [];
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
        if (seen.has(key)) {
          continue;
        }
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
      if (secondsLeft <= 0) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, WATCH_INTERVAL_MS));
    }
    return aggregated;
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
      if (tag === "a" || tag === "select" || tag === "textarea" || tag === "form") {
        return true;
      }
      if (tag === "input") {
        return ["", "submit", "button", "image", "reset", "password"].includes(type);
      }
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
        .map((key) => `${key}="${el.getAttribute(key) || ""}"`)
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

      let confidence = 45;
      if (disabled) confidence += 15;
      if (hidden) confidence += 10;
      if (actionable(el)) confidence += 10;
      if (riskWords.test(`${attrs} ${text}`)) confidence += 15;
      if (confidence > 100) confidence = 100;

      const severity =
        confidence >= 85 ? "HIGH" : confidence >= 60 ? "MEDIUM" : "LOW";
      pushFinding({
        url: location.href,
        type: "HIDDEN_OR_DISABLED_CONTROL",
        severity,
        confidence,
        title: "Client-side disabled/hidden control found in rendered DOM",
        summary:
          `Detected an actionable element that is ${
            disabled && hidden ? "disabled and hidden" : disabled ? "disabled" : "hidden"
          } on the client side.`,
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
            summary:
              `${storageName} contains a key/value pair that looks authentication- or secret-related.`,
            evidence: `${storageName}[${JSON.stringify(key)}] = ${trimmedValue}`,
            identity: `${storageName}|${key}`,
          });
        }
      }
    } catch (error) {}

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
          severity: /\beval\b|\bFunction\b/.test(match?.[0] || "") ? "MEDIUM" : "LOW",
          confidence: /\beval\b|\bFunction\b/.test(match?.[0] || "") ? 72 : 58,
          title: "Potential DOM XSS sink found in runtime script",
          summary:
            "Inline runtime script contains a dangerous DOM or code-execution sink worth manual review.",
          evidence: (match?.[0] || body).slice(0, 220),
          identity: `sink|${match?.[0] || body.slice(0, 80)}`,
        });
      }

      if (/addEventListener\s*\(\s*['"]message['"]|onmessage\s*=|postMessage\s*\(/i.test(body)) {
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
            /\/admin\b|\/internal\b/.test(lower) || isGraphql || kind === "websocket"
              ? "MEDIUM"
              : "INFO",
          confidence: isGraphql
            ? 90
            : entry.hasAuthHeader
              ? 86
              : kind === "fetch" || kind === "xmlhttprequest"
                ? 82
                : 74,
          title,
          summary: `The page context reported ${kind} activity during runtime instrumentation.`,
          evidence: `${evidence.slice(0, 260)}${entry.headerNames?.length ? ` | headers: ${entry.headerNames.join(",")}` : ""}${entry.graphqlOp ? ` | graphql: ${entry.graphqlOp}` : ""}${entry.hasAuthHeader ? " | auth-header" : ""}`.slice(0, 320),
          identity: `runtime-hook|${kind}|${method}|${url}|${body.slice(0, 40)}`,
        });
      }
    } catch (error) {}

    try {
      const resources = performance.getEntriesByType("resource") || [];
      for (const entry of resources) {
        const name = entry?.name || "";
        const initiatorType = (entry?.initiatorType || "").toLowerCase();
        if (!name) continue;
        if (!interestingInitiators.test(initiatorType) && !endpointWords.test(name)) {
          continue;
        }

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
    } catch (error) {}

    return out.slice(0, 120);
  }

  return {
    WATCH_DURATION_MS,
    collectSnapshotFindings,
    collectWatchedFindings,
  };
})();
