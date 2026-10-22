# Integration Plan — Sentinel Browser Security Engine Upgrade

**Document:** `docs/integration-plan.md`  
**Date:** 2026-10-22  
**Target Architecture:** Sentinel (`sentinel-trust-guardian`), Manifest V3  

---

## 1. Overview and Engineering Objectives

The objective is to upgrade Sentinel from a basic local-only scanner into a comprehensive, enterprise-grade website trust and phishing detection extension. We incorporate the best verified capabilities from **Site Inspector Pro**, **PhishShield**, **CertiLens**, and **Osprey**, while preserving Sentinel's existing modular TypeScript architecture, Manifest V3 compliance, and strict privacy guarantees.

---

## 2. Priority Classification and Improvement Inventory

### 2.1 P0: Critical Reliability, Mathematical Scoring, and Security Bugs

#### Improvement P0-1: Replace Linear Subtractive Scoring with Risk-Bounded Multi-Factor Scoring
* **Existing Implementation:** `src/security/trust-score.ts:assessWebsite` calculates `score = clampScore(100 - totalPenalty)` as a naive sum. Multiple weak or correlated penalties (e.g. 5 points for long URL, 4 points for subdomains, 8 points for mixed content) can unfairly depress a legitimate site's score. Furthermore, if critical findings exist, score is arbitrarily clamped to 39 without confidence weighting.
* **Reference Implementation:** Inspired by **CertiLens** (`background.js:computeRiskScore`) and bounded multi-layer models.
* **The Problem It Solves:** Prevents score inflation or accidental false positives, separates configuration warnings (missing headers) from confirmed malicious threats, and guarantees mathematical determinism across all input domains.
* **Proposed Implementation:** 
  - Restructure scoring into bounded categories: Transport Security (max penalty 25), Domain & Registration Integrity (max penalty 35), Phishing & Identity Deception (max penalty 75), Content & Script Behavior (max penalty 30), and Confirmed Threat Feeds (instant critical penalty 80+).
  - Calculate an explicit **evidence coverage ratio** and **confidence score** separately from the trust score.
  - Bound the total non-critical penalty to prevent a clean site from dropping below 40 due to minor missing headers or informational flags.
* **Dependencies & Permissions:** None. Pure TypeScript math in `src/security/trust-score.ts`.
* **API/Backend Requirements:** None.
* **Security & Privacy Implications:** Fully local; eliminates scoring inconsistencies.
* **Estimated Complexity:** Medium.
* **Tests Required:** Unit tests for boundary conditions (scores at 0, 39, 40, 79, 80, 100), penalty caps, and confidence calculations.
* **Classification:** Adaptation.

#### Improvement P0-2: Replace Deprecated Node `punycode` with Modern `tldts` or Modern Standards
* **Existing Implementation:** `package.json` and `src/security/url-analyzer.ts` import `toUnicode` from `punycode` (`^2.3.1`), triggering Node.js deprecation warnings `[DEP0040]` during testing and build.
* **Reference Implementation:** Standard URL parser / Web API / userland modern replacement.
* **The Problem It Solves:** Eliminates runtime deprecation warnings and future Node/V8 breakages.
* **Proposed Implementation:** Utilize native browser/Node `new URL().hostname` handling or safe userland decoding without deprecated modules.
* **Dependencies & Permissions:** Internal cleanup.
* **Estimated Complexity:** Low.
* **Tests Required:** Vitest unit test for IDN/Punycode normalization fixtures.
* **Classification:** Direct refactor.

---

### 2.2 P1: High-Value Phishing & Domain Intelligence Improvements

#### Improvement P1-1: Domain Registration & Age Intelligence via RDAP
* **Existing Implementation:** None. Sentinel only checks static TLD lists.
* **Reference Implementation:** **CertiLens** (`background.js:analyzeDomainAge`) and **Site Inspector Pro** (`popup.js:setupWhois`).
* **The Problem It Solves:** Over 70% of active phishing sites operate on domains registered less than 30 days prior. Without domain age, newly created brand-lookalike domains evade local list detection.
* **Proposed Implementation:**
  - Create `src/security/domain-age-checker.ts` and integrate with `pipeline.ts`.
  - Query IANA/RFC 7480 RDAP service (`https://rdap.org/domain/${domain}`) with an AbortController timeout (5s) and caching in `reputation-cache.ts`.
  - Calculate domain age in days.
  - Apply risk-weighted findings:
    * Age < 14 days: High risk (+30 penalty, "Newly registered domain")
    * Age < 30 days: Medium risk (+20 penalty, "Young domain")
    * Age < 90 days: Low risk (+10 penalty, "Domain registered within 3 months")
    * Age >= 365 days: Verified domain maturity (0 penalty)
  - Ensure failure/timeout is recorded as "Unavailable check" and never reported as safe or malicious.
* **Dependencies & Permissions:** Uses existing host permissions.
* **API/Backend Requirements:** Free public endpoint `https://rdap.org/domain/${domain}` (RFC 7480 standard, no API key needed).
* **Security & Privacy Implications:** Lookups only transmit the registrable domain (eTLD+1), never full URLs, paths, or query tokens.
* **Estimated Complexity:** Medium.
* **Tests Required:** Unit tests with mocked RDAP responses (recent domain, mature domain, timeout, 404/not found).
* **Classification:** Adaptation.

#### Improvement P1-2: Certificate Transparency (CT) Log Age Checking
* **Existing Implementation:** Sentinel's `certificate-checker.ts` only checks `protocol === 'https:'` and notes that raw certificate chains are inaccessible in MV3.
* **Reference Implementation:** **CertiLens** (`background.js:analyzeCertificateTransparency`).
* **The Problem It Solves:** Legitimate HTTPS certificates are issued months or years in advance, whereas phishing attacks use newly provisioned free certificates (Let's Encrypt / ZeroSSL) hours before attack launch.
* **Proposed Implementation:**
  - Create `src/security/ct-checker.ts`.
  - Query public Certificate Transparency logs via `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json` with a 6s timeout.
  - Compute the age of the newest and oldest certificate in days.
  - If newest cert is < 7 days old and domain shows heuristic suspicion, flag "Recently issued TLS certificate".
  - Gracefully handle crt.sh rate limits or downtime by setting status to `unavailable` with 0 penalty.
* **Dependencies & Permissions:** Uses existing host permissions.
* **API/Backend Requirements:** Free public endpoint `https://crt.sh`.
* **Security & Privacy Implications:** Transmits only the domain name. No user tokens.
* **Estimated Complexity:** Medium.
* **Tests Required:** Mock tests for new cert (<7d), mature cert, and API failure.
* **Classification:** Adaptation.

#### Improvement P1-3: DNS Security & Email Spoofing Authentication (SPF/DMARC)
* **Existing Implementation:** None.
* **Reference Implementation:** **CertiLens** (`background.js:analyzeDNS`) and **Site Inspector Pro** (`popup.js:setupSpfDmarc`).
* **The Problem It Solves:** Phishing campaigns frequently leverage domains with missing or unconfigured SPF and DMARC records to impersonate legitimate organizations in emails and web redirects.
* **Proposed Implementation:**
  - Create `src/security/dns-checker.ts`.
  - Query Cloudflare DNS over HTTPS (`https://cloudflare-dns.com/dns-query`) for TXT records of `${domain}` (SPF `v=spf1`) and `_dmarc.${domain}` (DMARC `v=DMARC1`).
  - Report whether SPF and DMARC policies (`p=reject`, `p=quarantine`, `p=none`) are enforced.
  - Missing records generate configuration findings, not automatic phishing verdicts.
* **Dependencies & Permissions:** Uses existing host permissions.
* **API/Backend Requirements:** Free public DoH endpoint `https://cloudflare-dns.com/dns-query`.
* **Security & Privacy Implications:** Domain name only. No user data transmitted.
* **Estimated Complexity:** Low-Medium.
* **Tests Required:** Unit tests for valid SPF/DMARC, missing SPF, missing DMARC, and DoH network error.
* **Classification:** Adaptation.

#### Improvement P1-4: Advanced Phishing Heuristics & DOM Brand Impersonation Mismatch
* **Existing Implementation:** Sentinel checks brand tokens in domain and Levenshtein lookalike distance.
* **Reference Implementation:** **PhishShield** (`extension/content.js:checkFakeLoginForms`, `extension/background.js:SIGNALS`).
* **The Problem It Solves:** Attackers often place login forms for major brands on unrelated generic or cloud domains (e.g. `xyz-portal.com` displaying "Sign in with your PayPal account").
* **Proposed Implementation:**
  - Enhance `src/content/index.ts` to inspect page title, H1/H2 headings, and logo alt text for top brands (PayPal, Microsoft, Google, Apple, Amazon, Netflix, Chase, etc.).
  - If brand name is prominent in identity elements but the page host is NOT in the brand's verified domains, flag `FAKE_LOGIN_BRAND_MISMATCH`.
  - Add URL heuristics from PhishShield: `@` symbol in authority (`https://brand.com@evil.com`), double slash redirect paths (`//`), non-standard ports (e.g. `:8443`, `:8888` on consumer domains), and `https` token embedded inside the hostname label.
  - Detect hidden iframes (`display:none`, `visibility:hidden`, `opacity:0`, `<5px`).
* **Dependencies & Permissions:** None. Handled in content script and URL analyzer.
* **Security & Privacy Implications:** Completely local; zero external network requests.
* **Estimated Complexity:** Medium.
* **Tests Required:** Unit tests with mock DOM structures for brand mismatch and URL parsing edge cases.
* **Classification:** Adaptation.

---

### 2.3 P2: Additional Security Audits & Threat Intelligence

#### Improvement P2-1: HTTP Security Header Audit
* **Existing Implementation:** None.
* **Reference Implementation:** **CertiLens** (`background.js:analyzeSecurityHeaders`).
* **The Problem It Solves:** Lack of HSTS, CSP, and X-Content-Type-Options exposes sites to man-in-the-middle attacks, clickjacking, and MIME confusion.
* **Proposed Implementation:**
  - Create `src/security/header-analyzer.ts`.
  - Execute a lightweight HTTP `HEAD` request from the background service worker when an assessable HTTPS page loads.
  - Audit presence and strength of:
    * `Strict-Transport-Security` (HSTS)
    * `Content-Security-Policy` (CSP)
    * `X-Frame-Options`
    * `X-Content-Type-Options`
    * `Referrer-Policy`
  - Explicitly document that missing headers are security posture findings, not proof of malicious intent.
* **Dependencies & Permissions:** Background `fetch` with existing host permissions.
* **Security & Privacy Implications:** Only issues standard HEAD request to the active page origin.
* **Estimated Complexity:** Medium.
* **Tests Required:** Unit tests for complete header set, partial header set, missing HSTS, and request timeout.
* **Classification:** Adaptation.

#### Improvement P2-2: Threat Intelligence Integration (URLScan & Pluggable Provider Interface)
* **Existing Implementation:** `ReputationService` supports only `LocalReputationProvider`.
* **Reference Implementation:** **CertiLens** (URLScan search API) and **Osprey** (monomorphic provider definitions with fallback & caching).
* **The Problem It Solves:** Local JSON lists cannot keep up with thousands of daily zero-day phishing campaigns.
* **Proposed Implementation:**
  - Implement `UrlScanReputationProvider` in `src/security/reputation.ts`.
  - Query `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=5` (read-only search, no key required).
  - Cache results in `reputationCache` (1-hour TTL).
  - Normalize verdicts into Sentinel's standard `ReputationResult` interface.
  - If provider fails or times out, degrade gracefully with `available: false` without penalizing clean domains.
* **Dependencies & Permissions:** Uses existing host permissions.
* **API/Backend Requirements:** Free public search endpoint on URLScan.io.
* **Security & Privacy Implications:** Searches registrable domain only, never user URLs with queries.
* **Estimated Complexity:** Medium.
* **Tests Required:** Unit test with mocked malicious URLScan verdict, clean verdict, rate limit, and timeout.
* **Classification:** Adaptation.

---

### 2.4 P3: User Interface & Transparency Enhancements

#### Improvement P3-1: Tabbed / Multi-Section Popup UI with Evidence Inspector
* **Existing Implementation:** Single static view with 4 summary items and 3 top factors.
* **Reference Implementation:** **Site Inspector Pro** (Tab routing: Overview, SSL/Headers, Domain/WHOIS, Threat Intel) & **CertiLens** (Evidence detail modal).
* **The Problem It Solves:** Users cannot see the actual evidence behind findings (e.g. which exact headers were missing, exact domain registration date, or which form destination was flagged).
* **Proposed Implementation:**
  - Upgrade `src/popup/main.tsx` with clean tabs:
    1. **Overview:** Trust score, risk badge, domain, confidence level, top factors, quick stats.
    2. **Domain & SSL:** Domain registration age, RDAP status, crt.sh certificate history, SPF/DMARC status.
    3. **Security Headers:** HSTS, CSP, X-Frame-Options, X-Content-Type-Options audit checklist.
    4. **Findings & Evidence:** Full list of all security findings with collapsible evidence inspection.
  - Add confidence badge (`High`, `Medium`, `Low`) based on evidence completeness.
* **Dependencies & Permissions:** React and Tailwind CSS.
* **Security & Privacy Implications:** Untrusted page titles and URLs sanitized via existing `sanitizeText`.
* **Estimated Complexity:** Medium.
* **Tests Required:** Component rendering tests in Vitest.
* **Classification:** Adaptation.
