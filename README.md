# ClientSideEye (Burp Extension)

ClientSideEye is a Burp Suite extension for enumerating client-side security issues in modern web applications. It combines Burp-side static analysis with optional browser-assisted runtime collection to surface risky UI gating, exposed client-side logic, browser-reachable endpoints, and runtime-only signals that do not appear in raw HTTP responses.

## Architecture

The codebase is intentionally split into a few focused layers:

- `ClientSideEyeExtension`: Burp entrypoint, menu registration, lifecycle, and bridge startup
- `core/`: static analyzers and finding/export models for HTML, JavaScript, source maps, and shared response analysis
- `integration/`: localhost browser bridge handling and browser-submitted finding normalization
- `ui/`: Burp Swing tab, filter state, table models, DevTools hint generation, and browser-view workflows
- `browser-extension/clientsideeye-bridge/`: companion browser helper for quick/deep runtime collection and bridge submission

Operationally, `Quick` paths favor lightweight static and current-DOM analysis, while `Deep` paths add temporary runtime instrumentation for SPA behavior and live network activity.

## Release 0.2.0

This release turns ClientSideEye from a narrow HTML helper into a broader client-side enumeration workflow:

- Burp-side analysis now covers HTML, JavaScript assets, and exposed source maps
- Browser-assisted scanning now supports quick and deep runtime collection
- Findings include runtime storage, script, and network signals alongside static evidence
- The localhost bridge is token-protected and better aligned with BApp security expectations
- The codebase is split more cleanly across analyzers, UI helpers, and bridge components

## Submission Summary

ClientSideEye is positioned as a focused client-side enumeration extension for Burp Suite. The goal is not to claim full browser-security coverage, but to give testers a practical workflow for surfacing client-side authorization anti-patterns, risky DOM/runtime behaviors, exposed routes/endpoints, and runtime-only clues that are easy to miss from proxy traffic alone.

BApp submission drafting notes are kept in [`BAPP_SUBMISSION.md`](BAPP_SUBMISSION.md).

## Quick Start (60 seconds)

1. Build and load extension JAR in Burp:
   - `./gradlew clean jar`
   - Burp `Extensions -> Installed -> Add` (Java), select built JAR
2. Confirm Burp output shows:
   - `[ClientSideEye] Browser bridge listening on http://127.0.0.1:<port> ...`
   - `[ClientSideEye] Browser bridge token: <token>`
3. Load unpacked browser bridge extension from:
   - `browser-extension/clientsideeye-bridge/`
4. In the Burp `ClientSideEye` tab, copy the displayed **Bridge Token**
5. Paste the token into the browser extension popup and click **Save Bridge Token**
6. Open target page, click browser extension button:
   - `Quick Scan + Send` for a fast DOM/runtime pass
   - or `Deep Scan (15s Runtime) + Send` for SPA/runtime changes and temporary network hooks
7. In popup, confirm:
   - `Bridge: http://127.0.0.1:<port>`
   - `Sent: <n>`
8. Open Burp `ClientSideEye` tab and triage findings.

## Browser Extension Setup

ClientSideEye includes a companion Chromium browser extension in:

- `browser-extension/clientsideeye-bridge/`

Load it as an unpacked extension, then click:

- `Quick Scan + Send`
- `Deep Scan (15s Runtime) + Send`

The popup should show:

- `Bridge: http://127.0.0.1:<port>`
- `Sent: <n>`

The popup now requires a per-session **Bridge Token** from the Burp extension tab.

## Features
- Detects plaintext password values in HTML
- Identifies hidden/disabled actionable UI controls
- Scores findings by severity and confidence
- Highlights high-risk issues in the UI
- Provides browser-friendly “find hints” for rapid validation
- Detects common DevTools blocking/detection logic and provides a bypass snippet
- Scans JavaScript for endpoint references, DOM XSS sinks, and postMessage usage
- Detects source map references and analyzes exposed `.js.map` responses
- Extracts runtime signals from the browser extension including storage tokens and inline script indicators
- Enumerates runtime network/API references from the browser using `performance` resource data
- Hooks page-context `fetch`, XHR, WebSocket, and EventSource usage during watch/scan sessions
- Exports findings as JSON
- Analyzes in-scope Site Map traffic
- Accepts runtime DOM findings via localhost Browser Bridge (for SPA/hash-route pages)
- Uses parsed HTML analysis via jsoup rather than regex-only tag matching
- Supports live search, host-scoped Site Map scans, and export of visible rows only

## Installation

### Recommended

1. Clone or download the repository
2. Use the top-level `ClientSideEye-Burp.jar` artifact, or rebuild it with `./gradlew clean jar`
3. In Burp Suite, open `Extensions -> Installed -> Add`
4. Choose `Extension type: Java`
5. Select `ClientSideEye-Burp.jar`

### Build from source

```bash
./gradlew clean jar
```

The build also refreshes the top-level `ClientSideEye-Burp.jar` file for easy loading into Burp.

## Screenshots

Burp findings view:

<img width="1501" height="855" alt="ClientSideEye findings view" src="https://github.com/user-attachments/assets/e3b67ed3-7893-4cf0-84a0-a0c50a0b4a99" />

Browser validation dialog:

<img width="901" height="553" alt="ClientSideEye browser validation dialog" src="https://github.com/user-attachments/assets/8ecc53e8-7bb3-4c67-b7cb-1c46e8870c54" />

## CI and Releases

- GitHub Actions runs `./gradlew clean check jar` on pushes and pull requests
- Version tags matching `v*.*.*` publish GitHub releases with both the root jar and versioned jar attached
- Local release workflow is available through `./scripts/release.sh`

## Usage

1. Browse the target application normally

2. Open the ClientSideEye tab

3. Click **Analyze Site Map (Quick)** or use right-click send-to from Proxy/HTTP History

4. Triage findings by Severity and Confidence

Notes:
- `Host filter` now also scopes Site Map scans when set.
- `Search` filters across title, type, URL, evidence, finding identity, and derived area.
- `Export visible rows only` exports the currently filtered set rather than the entire store.
- Site Map and right-click analysis now inspect both HTML responses and JavaScript assets when they look analyzable.
- JavaScript assets with `sourceMappingURL` comments and exposed `.js.map` responses are analyzed for extra client-side attack surface.

5. Use View in Browser to validate findings

### Validating Findings in the Browser

For each finding, ClientSideEye provides browser-friendly **Find Hints** to help you quickly locate the affected element in the DOM.

1. Select a finding in the **ClientSideEye** tab.
2. Click **View in Browser…**.
3. Click **Copy selected Find Hint**.
4. Paste the hint into your browser’s DevTools:
   - **Firefox**: Paste into the **Console** (recommended) or use it as a text search in the **Inspector**.
   - **Chrome/Chromium**: Paste into the **Console** or use it directly in the **Elements** search.

The Inspector will jump directly to the relevant element, allowing you to:
- Unhide or re-enable controls
- Inspect attributes and event handlers
- Manually validate whether server-side authorization is enforced

Notes:
- Find Hints now prefer `data-testid` when present (before generated IDs).
- Reveal snippet removes common disabled controls (`disabled`, `aria-disabled`, `pf-m-disabled`, `is-disabled`, `btn-disabled`).

## Finding Types

- `PASSWORD_VALUE_IN_DOM`
- `HIDDEN_OR_DISABLED_CONTROL`
- `ROLE_PERMISSION_HINT`
- `INLINE_SCRIPT_SECRETISH`
- `DEVTOOLS_BLOCKING`
- `JAVASCRIPT_ENDPOINT_REFERENCE`
- `DOM_XSS_SINK`
- `POSTMESSAGE_HANDLER`
- `STORAGE_TOKEN`
- `SOURCE_MAP_DISCLOSURE`
- `RUNTIME_NETWORK_REFERENCE`

## Browser Bridge (for Runtime DOM Findings)

ClientSideEye starts a local bridge server at:

- `http://127.0.0.1:<port>/api/health`
- `http://127.0.0.1:<port>/api/finding`

This lets an external browser extension or CLI submit findings from rendered DOM state (useful for SPA/hash routes where controls are not present in raw HTTP HTML).

Bridge port behavior:
- Default port is `17373`.
- If busy, ClientSideEye automatically tries `17374` to `17382`.
- Active port is logged in Burp extension output.
- A per-session bridge token is generated on startup and shown in the Burp tab/output.

### POST format

`Content-Type: application/x-www-form-urlencoded`

Required:

- `url`

Optional:

- `type` (defaults to `HIDDEN_OR_DISABLED_CONTROL`)
- `severity` (`HIGH|MEDIUM|LOW|INFO`, default `MEDIUM`)
- `confidence` (0-100, default `55`)
- `title`
- `summary`
- `evidence`
- `recommendation`
- `source`

Example:

```bash
curl -X POST "http://127.0.0.1:17373/api/finding" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "source=manual-test" \
  --data-urlencode "url=https://example.test/app#/settings" \
  --data-urlencode "type=HIDDEN_OR_DISABLED_CONTROL" \
  --data-urlencode "severity=MEDIUM" \
  --data-urlencode "confidence=75" \
  --data-urlencode "title=Client-side disabled save control in rendered DOM" \
  --data-urlencode "summary=Save action was disabled client-side and could be re-enabled in DevTools." \
  --data-urlencode "evidence=<button data-testid='save' aria-disabled='true' disabled>Save</button>"
```

### Included starter browser extension

A starter Chromium extension is included at:

- `browser-extension/clientsideeye-bridge/manifest.json`
- `browser-extension/clientsideeye-bridge/popup.html`
- `browser-extension/clientsideeye-bridge/popup.js`

It scans the current tab for actionable disabled/hidden controls and posts findings to the local bridge.

The popup also provides `Deep Scan (15s Runtime) + Send`, which repeatedly snapshots the active tab and installs temporary runtime hooks to catch SPA route changes and delayed rendering.

Runtime browser collection now also looks for:

- token- or secret-like values in `localStorage` / `sessionStorage`
- endpoint references in inline/runtime scripts
- dangerous DOM/code-execution sinks such as `innerHTML` and `eval`
- `postMessage` usage patterns
- runtime network/API requests referenced by `fetch`, XHR, scripts, and other observed resources
- page-context `fetch`, XHR, WebSocket, and EventSource activity captured during instrumentation windows

## BApp Positioning

ClientSideEye is intended as a focused client-side enumeration extension for Burp Suite.

The default Burp-side and browser-side actions are split conceptually into:

- `Quick` analysis for lightweight HTML/JS/DOM review
- `Deep` analysis for richer runtime instrumentation and SPA/runtime behavior

This keeps the common path lightweight while preserving a stronger runtime mode for advanced testing.

## Security Model

The Browser Bridge is intentionally bound to `127.0.0.1` only.

To reduce the risk of arbitrary web pages injecting spoofed findings into Burp:

- `POST /api/finding` requires a per-session bridge token
- CORS is only granted to browser extension origins
- request bodies are size-limited
- bridge sockets use read timeouts and worker handling to avoid a single stalled client blocking the bridge

## Development

Common local commands:

```bash
./gradlew test
./gradlew check
./gradlew clean jar
```

Project conventions:

- Keep Burp UI classes focused on coordination; move filtering, rendering, and scan orchestration into helpers
- Keep analyzers small and single-purpose; prefer coordinator classes over large heuristic buckets
- Treat the browser helper as a separate runtime collector with minimal UI/controller logic in `popup.js`
- Prefer comments that explain intent or tradeoffs, not line-by-line behavior

When changing browser-extension behavior, run `./gradlew check` so the Java build and browser script verification stay aligned.

## SPA/Hash Route Guidance

For routes like:

- `https://target/app/#/settings/localization`

the `#/...` fragment is client-side routing and often does not exist as a discrete server URL in Site Map.

Use one of these:
- Browser Bridge (recommended): send runtime DOM findings directly to ClientSideEye.
- Proxy/HTTP History send-to for underlying API responses and shell HTML.

## Troubleshooting

### Browser bridge port in use

If logs show:

- `Default port 17373 was busy. Using fallback port 17374.`

this is expected. Reload the browser bridge extension so it can probe the active port.

### Browser extension not sending findings

1. Confirm Burp output includes:
   - `Browser bridge listening on http://127.0.0.1:<port> ...`
   - `Browser bridge token: <token>`
2. Reload browser extension after any `manifest.json` change.
3. Copy the current token from the Burp `ClientSideEye` tab into the popup and click `Save Bridge Token`.
4. Re-open popup and run scan again.
5. Check popup status for:
   - `Bridge: http://127.0.0.1:<port>`
   - `Sent: <n>`

### Find Hint or Reveal snippet syntax errors

If Console shows `SyntaxError` for hint snippets, update to the latest build. Current hints emit quote-safe selectors, for example:

```js
inspect(document.querySelector('[data-testid="localization-tab-save"]'))
```

### False positives from source maps/assets

ClientSideEye skips non-HTML payloads (e.g., `.js.map`, `.js`, `.css`, images/fonts) during HTML analysis.  
If old findings remain, click **Clear Findings** and run analysis again.

## Non-goals

ClientSideEye does not exploit vulnerabilities or bypass authorization.
It highlights client-side anti-patterns for manual validation.

## Change Tracking

See `CHANGELOG.md` for changes, improvements, and feature requests.
