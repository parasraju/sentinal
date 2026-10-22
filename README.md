# Sentinel Trust Guardian

**Sentinel** is an advanced, privacy-first Chrome/Chromium Manifest V3 security extension for explainable website trust assessment, phishing detection, and privacy protection.

Upgraded using Reverse Engineering Analysis (REA) of leading open-source security tools (Site Inspector Pro, PhishShield, CertiLens, and Osprey), Sentinel combines high-speed local heuristics, in-depth DOM forensics, and privacy-preserving public registry intelligence to detect deceptive websites before credentials or private data are compromised.

---

## Key Capabilities

### 1. Unified Website Analysis Engine
- **Local URL & Phishing Heuristics:**
  - Detects `@` symbol credential confusion tokens.
  - Detects double-slash (`//`) path redirect tricks.
  - Identifies non-standard ports (ports outside standard 80 and 443).
  - Detects deceptive `https-` tokens embedded inside hostnames.
  - Identifies Punycode / Internationalized Domain Name (IDN) homograph attacks.
  - Detects raw IP address hostnames, suspicious TLDs, and URL shorteners.
- **In-DOM Forensics & Clickjacking Detection:**
  - Identifies hidden or zero-dimension iframes (`display:none`, `visibility:hidden`, `opacity:0`, `<5px`).
  - Brand mismatch detection: flags login pages claiming to represent major brands (Microsoft, Google, Apple, PayPal, Bank of America, Amazon) on unverified domains.
  - Sensitive form analysis: flags password, OTP, and payment forms submitting over unencrypted HTTP or to external third-party origins.

### 2. Domain & Transport Security Intelligence
- **RDAP Domain Registration Intelligence:**
  - Queries public RDAP registries (`https://rdap.org/domain/{domain}`) to inspect registration age and registrar details.
  - Flags high-risk newly registered domains (<14 days, <30 days, <90 days).
- **Certificate Transparency (crt.sh):**
  - Audits public Certificate Transparency logs to determine certificate issuance age and known issuers.
  - Differentiates mature SSL deployments from newly provisioned disposable TLS infrastructure.
- **DNS Security & Email Authentication (Cloudflare DoH):**
  - Performs DNS-over-HTTPS queries for SPF (`v=spf1`) and DMARC (`v=DMARC1`) records.
  - Detects domains configured with email servers (MX) that lack spoofing defenses.
- **HTTP Security Headers Audit:**
  - Non-invasive `HEAD` request audits: HSTS, Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.

### 3. Threat Intelligence
- **UrlScan Integration:**
  - Queries public threat intelligence feeds via domain-level lookups with timeout, rate-limit protection, and in-memory caching.
- **Local Curated Reputation:**
  - Bundled local reputation and tracker databases for instant, offline verification.

### 4. Deterministic Bounded Scoring Model
- Calculates a 0–100 score classified into:
  - **80–100:** Safe (Green)
  - **40–79:** Be Careful (Yellow / Caution)
  - **0–39:** Dangerous (Red)
- **Category Caps:** Deductions are capped per category (`transport`: 25, `domain`: 35, `phishing`: 75, `content`: 30, `reputation`: 100) to prevent false-positive accumulation from minor configuration oversights.
- **Critical Overrides:** High-confidence malicious reputation matches or verified credential theft automatically cap the score at 39.
- **Evidence Confidence Indicator:** Exposes a distinct confidence percentage based on evidence completeness.

### 5. Modern Tabbed User Interface
- **Overview Tab:** Score gauge, risk classification, critical alerts, security overview, and top factors.
- **Domain & SSL Tab:** RDAP domain age, registration/expiry dates, registrar name, Certificate Transparency logs, SPF, and DMARC policies.
- **Headers Tab:** Compliance score and interactive security header checklist with plain-English explanations.
- **Findings Tab:** Granular list of findings with severity badges, penalties, observable evidence inspection, and recommended remediation.
- **Export Feature:** One-click download of sanitized forensic JSON assessment reports.

---

## Privacy Architecture

1. **Zero Full-URL Leakage:** Remote lookups (RDAP, crt.sh, Cloudflare DoH, UrlScan) query strictly by registrable domain (`example.com`). Full URLs, path parameters, tokens, and query strings never leave the client.
2. **Zero Form-Data Access:** Form inspection analyzes DOM attributes (`<input type="password">`, `<form action="...">`) without reading entered keystrokes or submitted values.
3. **Graceful Fallbacks:** External network lookup failures return `available: false` with **0 penalty**. An unavailable check is never treated as proof of maliciousness or proof of safety.

---

## Installation & Testing in Chrome

1. **Build the extension:**
   ```powershell
   npm install
   npm run build
   ```
2. **Load in Chrome / Brave / Edge:**
   - Open your browser and navigate to `chrome://extensions/`.
   - Toggle **Developer mode** in the top-right corner.
   - Click **Load unpacked**.
   - Select the `dist/` directory inside this repository (`d:\p\quard\dist`).
3. **Verify:**
   - The Sentinel shield icon will appear in your browser toolbar.
   - Open any website and click the Sentinel icon to view the real-time trust score, domain intelligence, security headers, and findings.
   - After rebuilding, return to `chrome://extensions/`, click **Reload** on Sentinel, then refresh the website tab. An older unpacked bundle can continue showing the previous score logic.

### Score behavior

- A clean HTTPS page with complete page, cookie, and tracker evidence can legitimately score `100/100` because no material penalty was observed.
- HTTP pages receive a transport-security deduction and normally score below the equivalent HTTPS page.
- Suspicious URL, phishing, form, script, cookie, tracker, header, or reputation findings apply explicit penalties shown in the Findings view.
- If core evidence is unavailable, Sentinel displays `—` and `Unknown` rather than treating missing evidence as a safe `100`.
- The score is an estimate from observable evidence, not a guarantee of safety.

---

## Verification & Automated Test Suite

Sentinel maintains 100% test pass rate with zero linting warnings and zero typecheck errors:

```powershell
# Run TypeScript compilation check
npm run typecheck

# Run Vitest automated unit test suite (29 tests across 6 test suites)
npm test

# Run ESLint code quality audit
npm run lint

# Build production bundle
npm run build
```

---

## Documentation Deliverables

- [`docs/rea-baseline-audit.md`](docs/rea-baseline-audit.md): Phase 1 baseline audit, execution flow, and initial state.
- [`docs/reference-project-analysis.md`](docs/reference-project-analysis.md): Phase 2 deep-dive analysis of Site Inspector Pro, PhishShield, CertiLens, and Osprey.
- [`docs/integration-plan.md`](docs/integration-plan.md): Phase 3 prioritized integration plan (P0-P3).
- [`docs/trust-score-model.md`](docs/trust-score-model.md): Phase 5 bounded multi-category scoring formula and confidence model.
- [`docs/testing-and-validation.md`](docs/testing-and-validation.md): Phase 9 20-scenario testing and validation matrix.
