# ClientSideEye (Burp Extension)

ClientSideEye is a Burp Suite extension for identifying **client-side security anti-patterns**
such as hidden/disabled privileged controls and passwords rendered in HTML responses.

## Features
- Detects plaintext password values in HTML
- Identifies hidden/disabled actionable UI controls
- Scores findings by severity and confidence
- Highlights high-risk issues in the UI
- Provides browser-friendly “find hints” for rapid validation
- Exports findings as JSON
- Analyzes in-scope Site Map traffic

## Installation
1. Build the extension:
   ```bash
   gradle clean jar
2. In Burp Suite:

- Extensions → Installed → Add

- Extension type: Java

- Select the generated JAR

## Usage

1. Browse the target application normally

2. Open the ClientSideEye tab

3. Click Analyze Site Map (in-scope) or use right-click send-to (if enabled)

4. Triage findings by Severity and Confidence
<img width="1501" height="855" alt="image" src="https://github.com/user-attachments/assets/e3b67ed3-7893-4cf0-84a0-a0c50a0b4a99" />

6. Use View in Browser to validate findings
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

## Finding Types

- PASSWORD_VALUE_IN_DOM

- HIDDEN_OR_DISABLED_CONTROL

- ROLE_PERMISSION_HINT

- INLINE_SCRIPT_SECRETISH

## Non-goals

ClientSideEye does not exploit vulnerabilities or bypass authorization.
It highlights client-side anti-patterns for manual validation.
