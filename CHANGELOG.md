# Change Log

This file tracks changes, improvements, and feature requests for ClientSideEye-Burp.

## 0.2.0 - 2026-03-19

### Highlights
- Expanded static analysis beyond HTML into JavaScript assets and exposed source maps.
- Added browser-assisted quick and deep runtime collection for DOM, storage, and network signals.
- Hardened the localhost bridge with token authentication, tighter origin handling, size limits, and worker-thread request handling.
- Improved Burp-side triage with scoped Site Map scans, richer filters, visible-row export, and stronger DevTools find/highlight/reveal hints.
- Refactored the codebase into smaller analyzers, UI helpers, and bridge components with broader automated test coverage.

### Reviewer notes
- `./gradlew check` verifies Java tests and browser-extension script syntax.
- The browser bridge remains localhost-only and requires a per-session token from the Burp tab.
- Quick paths are designed to stay lightweight; deep paths add temporary runtime instrumentation for SPA behavior.

---

## 0.1.0 - 2026-01-31

### Changes
- Initial release.
