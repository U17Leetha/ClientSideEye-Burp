# BApp Submission Notes

This file is intended to make PortSwigger BApp submission easier by keeping the core review text in one place.

## Proposed Name

ClientSideEye

## One-line Summary

Burp extension for enumerating client-side security issues from HTML, JavaScript, source maps, and live browser runtime signals.

## Short Description

ClientSideEye helps testers find client-side authorization anti-patterns, hidden or disabled controls, risky DOM/runtime behaviors, exposed client-side routes and endpoints, and other browser-side clues that are often missed when reviewing proxy traffic alone.

## How It Works

ClientSideEye combines Burp-side static analysis with optional browser-assisted runtime collection.

- Burp-side analysis inspects HTML responses, JavaScript assets, and exposed source maps.
- The companion browser helper can send runtime findings from the rendered page, including DOM-only controls, storage signals, runtime network references, and client-side script indicators.
- Findings are triaged in a Burp tab with filtering, grouping, export, and browser validation hints.

## Setup Notes

- Load `ClientSideEye-Burp.jar` into Burp as a Java extension.
- Optionally load `browser-extension/clientsideeye-bridge/` as an unpacked Chromium extension.
- Copy the per-session bridge token from the Burp tab into the browser helper if runtime collection is needed.

## Why It Is Distinct

ClientSideEye is positioned as a focused client-side enumeration workflow rather than a generic scanner. Its main value is combining:

- static HTML, JavaScript, and source-map analysis inside Burp
- runtime collection from a live browser context
- DevTools-friendly find, highlight, and reveal guidance for rapid validation

The extension is intended to help testers surface client-side authorization anti-patterns, runtime-only controls, and browser-reachable attack surface that may not appear clearly in raw HTTP messages.

## Security Model

- The browser bridge binds only to `127.0.0.1`.
- `POST /api/finding` requires a per-session token.
- Bridge responses only grant CORS to browser extension origins.
- Request sizes are limited.
- The bridge uses timeouts and worker-thread handling to avoid a single stalled client blocking the server.
- The bridge token is masked by default in the Burp UI.

## Offline Support

The extension does not depend on any online service to function. Static analysis, Burp-side workflows, and the localhost bridge all work offline.

## Dependency and Packaging Notes

- The release jar includes runtime dependencies for one-click installation.
- The extension builds against the Montoya API artifact via Gradle.
- `./gradlew check` verifies Java tests and browser-extension script syntax.

## Large Project Notes

- Site Map analysis runs in background threads.
- Host scoping and scan limits are exposed in the UI.
- Large Site Map scans prompt before proceeding.
- Findings are capped in-memory to avoid unbounded growth.

## Suggested Reviewer Flow

1. Load the top-level `ClientSideEye-Burp.jar` into Burp.
2. Open the `ClientSideEye` tab and verify the browser bridge status/token display.
3. Run `Analyze Site Map (Quick)` on a scoped target.
4. Optionally load the bundled browser helper and run `Quick Scan + Send` or `Deep Scan (15s Runtime) + Send`.
5. Validate a finding using `View in Browser...` and the generated locate/highlight/reveal hints.

## Repository

- GitHub repository: `https://github.com/U17Leetha/ClientSideEye-Burp`
- Release artifact in repo root: `ClientSideEye-Burp.jar`
