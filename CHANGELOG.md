# Changelog

All notable changes to ClientSideEye-Burp are documented in this file.

The format is intentionally simple and release-oriented so external reviewers can quickly understand what changed between versions.

## [Unreleased]

## [0.2.0] - 2026-03-19

### Added
- JavaScript asset analysis for endpoint references, DOM XSS sinks, and `postMessage` handlers.
- Source map analysis for exposed `.js.map` responses and embedded source content.
- Browser-assisted quick and deep runtime collection for DOM, storage, script, and network signals.
- Stronger DevTools-oriented locate, highlight, and reveal hints for validating findings in the browser.
- More focused helper classes across analyzers, UI, and bridge handling.
- Additional automated coverage for analyzer, bridge, filter, and UI-helper behavior.

### Changed
- Expanded the extension from a narrow HTML-focused helper into a broader client-side enumeration workflow.
- Improved Burp-side triage with host-scoped Site Map scans, better filtering, visible-row export, and richer finding grouping.
- Refined the README and release documentation for external reviewers and BApp-style evaluation.
- Standardized the top-level build workflow so `./gradlew jar` refreshes the root `ClientSideEye-Burp.jar` artifact.

### Security
- Hardened the localhost browser bridge with per-session token authentication.
- Restricted bridge CORS behavior to browser extension origins.
- Added request size limits, socket timeouts, and worker-thread client handling.
- Masked the bridge token by default in the Burp UI while preserving explicit reveal/copy actions.

### Developer Notes
- `./gradlew check` verifies Java tests and browser-extension script syntax.
- Quick paths are intended to stay lightweight; deep paths add temporary runtime instrumentation for SPA behavior.
- The browser bridge remains localhost-only and requires a per-session token from the Burp tab.

## [0.1.0] - 2026-01-31

### Added
- Initial Burp Suite extension release.
- HTML analysis for hidden or disabled controls and password values rendered in the DOM.
- Basic find hints for validating findings in browser DevTools.
