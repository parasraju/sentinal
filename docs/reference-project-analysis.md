# REA Reference Project Analysis

**Analysis Date:** 2026-10-22  
**Auditor:** Senior Browser-Extension Cybersecurity Engineer  
**Inspection Tool:** REA (`rea-agents analyze-javascript-application`) & Static Code Trace  

---

## 1. Executive Summary & Comparison Matrix

All four reference repositories were cloned, inspected, traced, and analyzed using REA and filesystem static analysis. Below is the verified source-backed capability matrix:

| Capability | Existing Extension (Sentinel) | Reference A: Site Inspector Pro | Reference B: PhishShield | Reference C: CertiLens | Reference D: Osprey |
|---|---|---|---|---|---|
| **Trust score** | **Verified:** 0–100 deterministic score clamped with critical overrides (`assessWebsite` in `src/security/trust-score.ts`). | **Verified:** 0–100 heuristic score with weights for HTTPS, TLD, page signals (`calcTrustScore` in `popup.js:L46-72`). | **Verified:** 0–100 risk score (inverted: 0-39 safe, 40-69 suspicious, 70-100 phishing) (`analyzeURL` in `extension/background.js:L96-203`). | **Verified:** 0–100 additive risk penalty score with 4 tiers (Low, Medium, High, Critical) (`computeRiskScore` in `background.js:L514-610`). | **Verified:** Multi-provider binary or threshold-based blocking verdict per category (`checkUrl` in `background.js`). |
| **HTTPS and certificate checks** | **Verified:** Observes browser-loaded protocol & mixed content; acknowledges MV3 lack of raw TLS chain access (`src/security/certificate-checker.ts`). | **Verified:** Checks `https:` protocol and mixed content images/scripts/iframes (`renderSSL` and `setupMixedContent` in `popup.js:L540-569`). | **Verified:** Flags password fields on unencrypted HTTP pages (`CREDENTIAL_FIELDS` in `extension/content.js:L29-35`). | **Verified:** Queries public Certificate Transparency logs via crt.sh API (`analyzeCertificateTransparency` in `background.js:L178-233`); calculates cert age. | **Verified:** Validates HTTPS enforcement through policy service and webNavigation hooks (`url-service.js`). |
| **Phishing detection** | **Verified:** Brand token matching, Levenshtein distance, sensitive form on deceptive host (`detectPhishing` in `src/security/phishing-detector.ts`). | **Verified:** Keyword regex, suspicious TLDs, naive brand name substring check (`content.js:L17-76`). | **Verified:** 30+ regex patterns, IP as host, @ symbol, double slash, dashes, fake login form (`extension/background.js:L55-93`). | **Verified:** Parallel analysis combining CT age, domain age, security headers, DoH, and DOM indicators (`background.js:L514-610`). | **Verified:** Multi-feed threat intel matching against 20+ commercial/open feeds (`provider-engine.js`). |
| **Lookalike-domain detection** | **Verified:** Punycode decoding, mixed-script detection, Levenshtein skeleton confusable mapping (`skeleton` & `inspectChunks` in `src/security/url-analyzer.ts:L35-172`). | **Verified:** Substring matching of brand names against non-whitelisted hostnames (`content.js:L23-26`). | **Verified:** Punycode `xn--` detection, character substitution regex (`paypa1`, `g00gle`, `amaz0n`) (`extension/background.js:L55-69,154-157`). | **Verified:** Unicode confusable character map, mixed Cyrillic/Greek/Latin script detection, normalized hostname recovery (`analyzeHomograph` in `background.js:L90-126`). | **Verified:** Hostname-level regex and canonical domain comparison (`url-service.js`). |
| **Domain intelligence** | **Verified (Limited):** TLD check, IP host, URL shorteners; no live registration or DNS lookups. | **Verified:** RDAP lookup (`rdap.org`), Wayback Machine earliest archive date (`archive.org`), Cloudflare DoH (`popup.js:L209-276,428-498`). | **Verified (Limited):** TLD list, URL shorteners list, IP regex; local lists only (`extension/background.js:L81-93`). | **Verified:** RDAP registration age (`rdap.org`), Cloudflare DoH SPF/DMARC query (`analyzeDomainAge` & `analyzeDNS` in `background.js:L296-447`). | **Verified:** Domain categorization via backend partner feeds (`domain-intel.js`). |
| **Security headers** | **Not verified (Absent):** Sentinel currently does not inspect HTTP response headers. | **Not verified (Absent):** Claims header audit in description but only inspects DOM metadata in code. | **Not verified (Absent):** Does not check HTTP headers. | **Verified:** Async HTTP `HEAD` request checking CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy (`analyzeSecurityHeaders` in `background.js:L240-293`). | **Verified:** Enforces CSP on internal extension pages; passes headers through proxy. |
| **Threat-intelligence APIs** | **Verified (Local only):** Bundled static JSON `known-bad-domains.json` (no remote API calls). | **Verified:** Unofficial Google Safe Browsing via public Transparency Report endpoint (`setupSafeBrowsing` in `popup.js:L403-425`). | **Not verified (Planned):** Documents optional Google Safe Browsing and PhishTank in README, but uninstalled in code. | **Verified:** URLScan.io search API (`https://urlscan.io/api/v1/search/?q=domain:...`) (`analyzeThreatIntel` in `background.js:L454-500`). | **Verified:** 20+ threat intelligence provider integrations routed via anonymized proxy `https://api.osprey.ac/` (`proxy-builtins.js`). |
| **Local analysis** | **Verified:** Full client-side analysis of URL, DOM forms, scripts, cookies, DNR rules without remote dependencies. | **Verified:** Local DOM metadata scraping and synchronous scoring in `content.js`. | **Verified:** 100% local analysis, zero external API keys required (`extension/background.js`). | **Verified:** Local DOM scanner, homograph analysis, and heuristic aggregation (`content.js`). | **Verified:** Local blocklist caching, regex evaluations, and rule evaluations (`response-rule-engine.js`). |
| **Warning and blocking** | **Verified:** In-page warning banner for critical risks, form submission interception, toolbar badge. | **Verified:** In-page popup floating modal (`__site_inspector_popup__` in `content.js:L80-250`). | **Verified:** Chrome badge icons (`✓`, `!`, `✗`) and standalone warning interstitial (`extension/warning.html`). | **Verified:** Badge color, popup warning cards, detailed findings modal (`popup.js`). | **Verified:** Interstitial block page with proceed override, telemetry exclusion, and false-positive reporting (`pages/warning/warning-page.js`). |

---

## 2. Deep Dive: Reference A — Site Inspector (Trust Checker Pro)
* **Repository:** `https://github.com/dasaradhi-varma/site-inspector-pro`
* **License:** MIT License (`LICENSE`)
* **Manifest:** Manifest V3 (`background.js` service worker, `content.js` idle script, `popup.html` / `popup.js`).
* **Permissions:** `activeTab`, `scripting`, `storage`, host permissions `<all_urls>`.

### 2.1 Security Algorithms & Key Findings
1. **RDAP Domain Registration Intelligence (`popup.js:L209-276`):**
   - Implements `setupWhois(hostname)` using public RFC 7480 endpoint: `https://rdap.org/domain/${domain}`.
   - Extracts `registration` and `expiration` event dates without requiring an API key.
   - Computes domain age in years: `ageYears = ((now - regDate) / (1000 * 60 * 60 * 24 * 365)).toFixed(1)`.
   - **Limitation:** Only executed when the user manually clicks "Run WHOIS Lookup" in the popup. Does not contribute proactively to initial score calculation.

2. **DNS & Email Authentication Over HTTPS (`popup.js:L470-537`):**
   - Implements `setupDnsBlacklist()` and `setupSpfDmarc()` via Cloudflare DNS over HTTPS:
     `https://cloudflare-dns.com/dns-query?name=${domain}&type=TXT` with header `Accept: application/dns-json`.
   - Searches Answer records for `v=spf1` and `_dmarc.${domain}` for `v=DMARC1`.
   - Evaluates spoofing risk: Missing both SPF and DMARC indicates `HIGH` spoofing risk.

3. **Wayback Machine Historical Age (`popup.js:L428-466`):**
   - Queries `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=1&fl=timestamp,statuscode&from=19900101&to=20251231&filter=statuscode:200` to find the earliest snapshot date.
   - Useful for verifying if a domain had active content years ago vs newly created.

4. **Mixed Content Detection (`popup.js:L540-569`):**
   - Uses `chrome.scripting.executeScript` to query `img[src^="http:"]`, `script[src^="http:"]`, `link[href^="http:"]`, `iframe[src^="http:"]`.
   - Accurately enumerates mixed passive and active content.

5. **Payment Form Heuristics (`popup.js:L572-600`):**
   - Scans DOM for credit card inputs (`input[name*="card"]`, `input[autocomplete*="cc-"]`), CVV inputs, Stripe elements, and checkout form actions.

---

## 3. Deep Dive: Reference B — PhishShield
* **Repository:** `https://github.com/SiranjeeviE/PhishShield`
* **License:** MIT License
* **Manifest:** Manifest V3 (`extension/manifest.json`).
* **Permissions:** `tabs`, `storage`, `webNavigation`, host permissions `<all_urls>`.

### 3.1 Security Algorithms & Key Findings
1. **URL Phishing Heuristics (`extension/background.js:L96-203`):**
   - Weighted signal architecture:
     * `IP_AS_HOST` (+80 points risk)
     * `BRAND_TYPOSQUAT` (+85 points risk)
     * `KNOWN_PHISH_PATTERN` (+90 points risk)
     * `HOMOGRAPH_ATTACK` (+70 points risk)
     * `HTTPS_TOKEN_IN_DOMAIN` (+50 points risk) — e.g. `https-secure-login.com`
     * `AT_SYMBOL_IN_URL` (+35 points risk) — e.g. `https://legit.com@phish.com`
     * `DOUBLE_SLASH` (+25 points risk) — open redirect pattern
     * `SUSPICIOUS_PORT` (+40 points risk) — ports other than 80, 443, 8080, 8443
   - Includes trusted domains allowlist (`TRUSTED_DOMAINS`) to prevent false positives on primary services.

2. **DOM-Level Fake Login & Brand Mismatch (`extension/content.js:L79-99`):**
   - Detects fake login forms: If page contains password field + username field, but page text/title contains a well-known brand (e.g. `PayPal`, `Google`, `Chase`) while `location.hostname` does NOT belong to that brand.
   - Flags `FAKE_LOGIN_FORM` with high risk (+60 points).

3. **Hidden Iframe Detection (`extension/content.js:L63-77`):**
   - Inspects computed styles of `<iframe>` elements:
     `style.display === "none" || style.visibility === "hidden" || style.opacity === "0" || (width < 5 && height < 5)`.
   - Prevents stealth credential harvesting or clickjacking.

4. **Standalone Warning Page (`extension/warning.html`):**
   - Dedicated full-page interstitial blocking dangerous sites with detailed signal explanations and an option to return to safety.

---

## 4. Deep Dive: Reference C — CertiLens
* **Repository:** `https://github.com/JalenTechHub/CertiLens`
* **License:** GNU General Public License v3.0 (GPLv3)
* **Manifest:** Manifest V3 (`manifest.json`).
* **Permissions:** `tabs`, `storage`, `webNavigation`, host permissions `<all_urls>`.

### 4.1 Security Algorithms & Key Findings
1. **Certificate Transparency (CT) Age via crt.sh (`background.js:L178-233`):**
   - Queries `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json` with 10s timeout and retries.
   - Parses `not_before` timestamps across all certificates for the domain.
   - Computes `newestCertDays` and `oldestCertDays`.
   - High-confidence signal: Certificates issued `< 7 days ago` contribute +30 risk points; `< 30 days ago` contribute +15 risk points.
   - **Crucial Chrome Extension Insight:** Directly solves the MV3 restriction where extension scripts cannot read the live X.509 certificate chain. Querying public CT logs via `crt.sh` is completely legal in MV3 and provides true certificate issuance age!

2. **HTTP Security Header Audit (`background.js:L240-293`):**
   - Executes an asynchronous `fetch(url, { method: 'HEAD' })` from the background service worker.
   - Evaluates presence and validity of:
     * `content-security-policy` (CSP)
     * `strict-transport-security` (HSTS)
     * `x-frame-options`
     * `x-content-type-options`
     * `referrer-policy`
     * `permissions-policy`, `cross-origin-opener-policy` (COOP), `cross-origin-embedder-policy` (COEP)
   - Accurately treats missing headers as configuration weaknesses (+15–25 points risk) rather than conclusive evidence of phishing.

3. **Parallel Execution Architecture (`background.js:L53-73`):**
   - Uses `Promise.allSettled()` to launch all 6 security checks concurrently:
     * crt.sh Certificate Transparency
     * HTTP HEAD security headers
     * RDAP domain registration age
     * Cloudflare DoH (SPF, DMARC, MX, A)
     * URLScan.io threat intelligence
     * DOM content scan
   - Scan latency is bounded by the slowest single query (~2s) rather than sequential accumulation (~15s).

4. **Homograph & Confusable Detection (`background.js:L90-126`):**
   - Maps Cyrillic/Greek confusables (`а`, `е`, `о`, `р`, `с`, `х`, `ο`, `ρ`, `ν`, `α`, `ε`) and digit substitutions (`0` for `o`, `1` for `l`, `rn` for `m`).
   - Normalizes and recovers the intended brand domain.

5. **Threat Intelligence via URLScan.io (`background.js:L454-500`):**
   - Queries `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=5` (free, no API key required for reads).
   - If previous scans concluded `verdicts.overall.malicious === true`, applies a severe +50 risk penalty.

---

## 5. Deep Dive: Reference D — Osprey (Browser Protection)
* **Repository:** `https://github.com/OspreyProject/Osprey`
* **License:** GNU General Public License v3.0 (GPLv3)
* **Manifest:** Manifest V3 (`src/main/manifest.json`).
* **Permissions:** `tabs`, `storage`, `webNavigation`, `alarms`, `contentSettings`.
* **Host Permissions:** Restricted to `https://api.osprey.ac/*`.

### 5.1 Security Algorithms & Key Findings
1. **Architectural Verification & Metadata:**
   - Osprey is an established open-source browser security extension active across Chrome, Edge, and Firefox.
   - Integrates 20+ threat intelligence partners (AlphaMountain, BforeAI PreCrime, Cloudflare Radar, Spamhaus, etc.).

2. **Privacy-Preserving Proxy Architecture (`proxy-builtins.js`):**
   - **Design Pattern:** Rather than embedding 20 third-party API keys in the client extension or making direct client requests that leak user browsing history to dozens of commercial endpoints, Osprey routes lookups through an anonymized backend proxy `https://api.osprey.ac/`.
   - Distinguishes `lookupTarget: 'hostname'` from `lookupTarget: 'url'`. Sensitive URLs are truncated to registrable domain/hostname only, preventing query parameters or tokens from leaking.

3. **Provider Fallback & Normalized Finding Format:**
   - Provider definitions are monomorphic objects with standardized `report`, `endpoint`, and `blockCategories` shapes.
   - Provider failures degrade gracefully without blocking navigation or falsely flagging clean sites.

---

## 6. Synthesis & Reusable Implementations for Sentinel

From this REA analysis, the most compatible, highest-value improvements to integrate into Sentinel are:

1. **From CertiLens:**
   - Certificate Transparency age via `crt.sh` (`https://crt.sh/?q=${domain}&output=json`).
   - Security Header auditing via async HTTP `HEAD` request (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
   - Parallel `Promise.allSettled()` orchestration pattern for external intelligence.
   - URLScan.io public search API integration for live threat-intel signals.

2. **From Site Inspector Pro:**
   - RFC 7480 RDAP domain registration age lookup via `https://rdap.org/domain/${domain}`.
   - Cloudflare DNS-over-HTTPS (`https://cloudflare-dns.com/dns-query`) for SPF (`v=spf1`) and DMARC (`v=DMARC1`) records.
   - Enhanced mixed-content detection and payment form heuristics.

3. **From PhishShield:**
   - Additional URL phishing heuristics: `@` symbol in URL, double slash redirect, non-standard ports, `https-` in domain name token.
   - DOM-level fake login form detection with brand mismatch (detecting brand keywords in page title/headings while hosted on unrelated domains).
   - Hidden iframe heuristic detection (`display:none`, `visibility:hidden`, `<5px`).

4. **From Osprey:**
   - Privacy-first domain-level lookups (querying external providers strictly with registrable domain/hostname, never full URL with query strings).
   - Modular provider interfaces with timeouts, caching, and graceful failure fallbacks.
