# Sentinel security model

## Threat model

Sentinel is designed to reduce phishing, deceptive form, unsafe connection, and common privacy risks for Chromium users. It is not an antivirus, a browser isolation boundary, a certificate authority, or a guarantee that a site is safe.

## Privacy guarantees

- No backend, account, analytics, or remote AI service is used by default.
- Page collection is metadata-only. Passwords, OTPs, card numbers, clipboard contents, keystrokes, and form values are not read or stored.
- URLs are sanitized to origin, host, and path before persistence or export. Query strings, fragments, and embedded credentials are removed.
- Assessment history is minimal and bounded. Users can clear history or all local Sentinel data from Settings.

## Protection behavior

Tracker blocking uses only bundled declarativeNetRequest rules and validated allowlist rules. Strict mode can break embeds, videos, login providers, or other site functionality. Cookie deletion is explicit and can sign users out.

## False positives and false negatives

Unfamiliar domains, HTTP, long URLs, IP addresses, uncommon TLDs, cross-origin payment providers, and event handlers are not treated as proof of maliciousness. Conversely, a clean score cannot detect server-side abuse, newly registered domains, compromised legitimate sites, or behavior outside extension observability.

## Reporting a security issue

Do not include passwords, tokens, cookies, or private browsing history in a report. Provide a minimal reproducible page fixture or sanitized metadata whenever possible.
