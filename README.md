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

5. Use View in Browser to validate findings

## Finding Types

- PASSWORD_VALUE_IN_DOM

- HIDDEN_OR_DISABLED_CONTROL

- ROLE_PERMISSION_HINT

- INLINE_SCRIPT_SECRETISH

## Non-goals

ClientSideEye does not exploit vulnerabilities or bypass authorization.
It highlights client-side anti-patterns for manual validation.
