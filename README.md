# ClientSideEye (Burp Extension)

ClientSideEye is a Burp Suite extension for identifying **client-side security anti-patterns**
such as hidden/disabled privileged controls and passwords rendered in HTML responses.

## Quick Start (60 seconds)

1. Build and load extension JAR in Burp:
   - `gradle clean jar`
   - Burp `Extensions -> Installed -> Add` (Java), select built JAR
2. Confirm Burp output shows:
   - `[ClientSideEye] Browser bridge listening on http://127.0.0.1:<port> ...`
3. Load unpacked browser bridge extension from:
   - `browser-extension/clientsideeye-bridge/`
4. Open target page, click browser extension button:
   - `Scan Current Tab + Send to ClientSideEye`
5. In popup, confirm:
   - `Bridge: http://127.0.0.1:<port>`
   - `Sent: <n>`
6. Open Burp `ClientSideEye` tab and triage findings.

## Features
- Detects plaintext password values in HTML
- Identifies hidden/disabled actionable UI controls
- Scores findings by severity and confidence
- Highlights high-risk issues in the UI
- Provides browser-friendly “find hints” for rapid validation
- Detects common DevTools blocking/detection logic and provides a bypass snippet
- Exports findings as JSON
- Analyzes in-scope Site Map traffic
- Accepts runtime DOM findings via localhost Browser Bridge (for SPA/hash-route pages)

## Installation

### Recommended


1. Download the latest ```ClientSideEye-Burp.jar```
2. In Burp Suite:

- Extensions → Installed → Add

- Extension type: Java

- Select the generated JAR

### Build from source
1. Build the extension:
   ```bash
   gradle clean jar
   ```

## Usage

1. Browse the target application normally

2. Open the ClientSideEye tab

3. Click **Analyze Site Map (in-scope)** or use right-click send-to from Proxy/HTTP History

4. Triage findings by Severity and Confidence
<img width="1501" height="855" alt="image" src="https://github.com/user-attachments/assets/e3b67ed3-7893-4cf0-84a0-a0c50a0b4a99" />

5. Use View in Browser to validate findings
<img width="901" height="553" alt="image" src="https://github.com/user-attachments/assets/8ecc53e8-7bb3-4c67-b7cb-1c46e8870c54" />
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

- PASSWORD_VALUE_IN_DOM

- HIDDEN_OR_DISABLED_CONTROL

- ROLE_PERMISSION_HINT

- INLINE_SCRIPT_SECRETISH
- DEVTOOLS_BLOCKING

## Browser Bridge (for Runtime DOM Findings)

ClientSideEye starts a local bridge server at:

- `http://127.0.0.1:<port>/api/health`
- `http://127.0.0.1:<port>/api/finding`

This lets an external browser extension or CLI submit findings from rendered DOM state (useful for SPA/hash routes where controls are not present in raw HTTP HTML).

Bridge port behavior:
- Default port is `17373`.
- If busy, ClientSideEye automatically tries `17374` to `17382`.
- Active port is logged in Burp extension output.

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
2. Reload browser extension after any `manifest.json` change.
3. Re-open popup and run scan again.
4. Check popup status for:
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
