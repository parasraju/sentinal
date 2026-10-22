# Sentinel architecture

Sentinel is a Manifest V3 extension with local-first, evidence-based processing.

## Runtime flow

1. `src/content/index.ts` collects page metadata only: sanitized URL metadata, form destinations, field types, script signatures, and observable resource hosts. It never reads values, keystrokes, clipboard contents, or executes suspicious code.
2. `src/background/service-worker.ts` coordinates navigation events, content evidence, cookie access, reputation lookup, tracker analysis, trust scoring, storage, badges, and warnings.
3. `src/security/*` is browser-independent scoring and classification logic. Findings have stable IDs, evidence, severity, confidence, remediation, and an explicit penalty.
4. `src/browser/*` contains Chrome adapter calls for tabs, cookies, permissions, and declarativeNetRequest.
5. `src/popup/*` and `src/options/*` are React interfaces. They consume typed messages and never directly inspect page data.
6. `src/reports/*` creates a sanitized report from a snapshot. Query strings and form values are excluded before storage and export.

## Permissions

- `storage`: local settings, short assessment history, reputation cache, and session snapshots.
- `tabs`, `activeTab`, `scripting`: identify and inspect the active HTTP(S) tab when a content script is unavailable.
- `cookies`: inspect and delete selected cookies after browser permission checks.
- `webNavigation`: trigger assessment after top-frame navigation.
- `declarativeNetRequest`, `declarativeNetRequestFeedback`: enable bundled tracker rules and report matched-rule counts where Chromium exposes them.
- HTTP(S) host access: required for site-wide content metadata and DNR matching. Browser-internal and local-file pages remain unsupported.

The default `manifest.json` is the Chrome MV3 build and keeps a service worker because Chrome versions before 121 reject MV3 background `scripts`. Firefox and Safari builds should use the packaged `manifest.firefox.json` variant, which selects the same bundled module as an event-page background script. DNR feedback is optional in the default manifest because matched-rule diagnostics are non-essential and may be unavailable in other browsers.

## Scoring

The score starts at 100, applies each stable finding penalty once, clamps to 0-100, and exposes the factors that drove the result. HTTPS contributes explanatory evidence but no safety guarantee. Missing evidence is represented as unavailable or unknown.

## Known browser limits

The extension cannot independently inspect a complete TLS certificate chain, see every request body, verify a final server-side redirect recipient, identify all trackers, or prove malicious intent from a JavaScript event handler. Sentinel reports these limits instead of making those claims.
