# Sentinel Trust Score Model & Scoring Specification

**Document:** `docs/trust-score-model.md`  
**Version:** 2.0.0  
**Status:** Approved Specification  

---

## 1. Principles and Design Goals

1. **Deterministic & Evidence-Backed:** Identical inputs and observable evidence must yield the exact same score and findings every time.
2. **Explainable:** Every penalty maps directly to a discrete, observable finding with evidence, severity, remediation, and point deduction.
3. **No Double-Counting Correlated Signals:** Heuristics that measure similar aspects (e.g. brand in subdomain + brand lookalike + login term) are bounded within a category maximum so cumulative penalties do not inflate unnaturally.
4. **Honest Handling of Missing Data:** A missing or failed API check (e.g. RDAP timeout, crt.sh rate-limit) is marked as `unavailable` with **zero penalty** and adjusts the **confidence rating** downward. Unavailable data is never interpreted as proof of safety or guilt.
5. **Separation of Posture vs Malice:** Missing optional security headers (e.g. Permissions-Policy) or a new domain are configuration posture observations, not proof of fraud. High severity / critical penalties are reserved for confirmed threat intelligence or high-confidence credential theft combinations.
6. **Separate Confidence Metric:** Score reflects estimated trustworthiness (0–100); Confidence reflects evidence coverage (`high`, `medium`, `low`).

---

## 2. Score Range and Classifications

| Range | Classification | Indicator Color | Semantic Meaning |
|---|---|---|---|
| **80 – 100** | **Safe** | Green (`#0f9f6e`) | Strong trust signals, verified identity/domain maturity, valid encryption, no risk indicators. |
| **40 – 79** | **Be Careful** | Yellow / Amber (`#b45309`) | Noticeable configuration weaknesses, young domain, missing email auth, or moderate heuristics. Proceed with caution. |
| **0 – 39** | **Dangerous** | Red (`#b91c1c`) | Critical threats: confirmed phishing/malware, brand impersonation on deceptive domain, credential theft indicators. |
| **null** | **Unknown** | Slate (`#475569`) | Non-assessable page (internal browser page, local file) or URL-only missing evidence. |

---

## 3. Mathematical Formula and Bounded Categories

The score starts at a baseline of **100 points** and applies bounded risk deductions across 5 independent security categories:

$$\text{Raw Score} = 100 - \sum_{i=1}^{5} \min\left(P_i, \text{CategoryCap}_i\right)$$

$$\text{Final Score} = \begin{cases} 
\min(\text{Raw Score}, 39), & \text{if } \text{hasCriticalFinding} = \text{true} \\
\text{clamp}(\text{Raw Score}, 0, 100), & \text{otherwise}
\end{cases}$$

### Category Breakdown and Maximum Caps

| Category ($i$) | Description | Maximum Deduction ($\text{CategoryCap}_i$) | Example Penalties |
|---|---|---|---|
| **1. Transport & Connection** | Protocol, TLS errors, mixed content, security headers. | **25 pts** | Plain HTTP: -20; Mixed active content: -15; Missing HSTS + CSP: -10; Missing headers only: -5. |
| **2. Domain Integrity & DNS** | Registration age, certificate age, SPF/DMARC email auth. | **35 pts** | Domain age < 14d: -25; Age < 30d: -15; Cert age < 7d: -20; Missing SPF + DMARC: -10; Suspicious TLD: -8. |
| **3. Phishing & Brand Deception** | Punycode, homographs, brand lookalike, deceptive forms. | **75 pts** | Confirmed brand lookalike: -35; Credential form on deceptive domain: -40; Hidden iframe: -15; Fake login: -35. |
| **4. Content & Script Behavior** | Obfuscated JS, suspicious form actions, risky event handlers. | **30 pts** | External sensitive form: -25; Obfuscated JS patterns: -15; Insecure form action: -15; Key/clipboard sniffers: -10. |
| **5. Threat Intelligence Feeds** | Confirmed matches from local reputation list, URLScan, etc. | **100 pts** | Local bad list match: -80; URLScan malicious verdict: -70. *Automatically flags critical override.* |

---

## 4. Evidence Coverage & Confidence Score

Confidence is computed from observable evidence layers:

$$\text{Coverage Score} = W_{\text{URL}} + W_{\text{DOM}} + W_{\text{Cookies}} + W_{\text{Headers}} + W_{\text{Domain}} + W_{\text{ThreatIntel}}$$

Where weights are:
- $W_{\text{URL}} = 0.20$ (URL parsed & normalized)
- $W_{\text{DOM}} = 0.25$ (Content script reported page metadata)
- $W_{\text{Cookies}} = 0.10$ (Cookies accessible & analyzed)
- $W_{\text{Headers}} = 0.15$ (HTTP response headers audited)
- $W_{\text{Domain}} = 0.15$ (RDAP or DNS DoH completed)
- $W_{\text{ThreatIntel}} = 0.15$ (Reputation / threat intelligence check completed)

### Confidence Levels:
- **High Confidence ($\ge 0.70$):** DOM evidence present, headers or domain intelligence verified.
- **Medium Confidence ($0.40 - 0.69$):** Partial evidence (e.g. URL + DOM, but external lookups timed out).
- **Low Confidence ($< 0.40$):** URL-only analysis (content script blocked or external page uninspected).

---

## 5. Critical Finding Overrides

A site is immediately classified as **Dangerous** with score clamped to $\le 39$ if any of the following critical conditions are met:
1. Confirmed local bad list or external threat intelligence match (`reputation:known-phishing`, `threat-intel:malicious`).
2. High-confidence brand impersonation combined with sensitive credential/payment collection.
3. Form with password/card submission pointing to an unverified external third party or `javascript:` URI on a non-trusted origin.
4. Plain HTTP connection requesting sensitive account passwords or credit card data.

---

## 6. Boundary Conditions & Test Scenarios

The model is verified against all primary boundary points:
* **Score = 100:** Clean HTTPS website, mature domain (>1 year), valid HSTS/CSP, valid SPF/DMARC, clean reputation, no tracker/script concerns.
* **Score = 80:** Edge of Safe classification (minor configuration deductions, e.g., missing optional header and minor analytics tracker).
* **Score = 79:** Edge of Caution classification (e.g., domain registered 60 days ago or minor mixed passive content).
* **Score = 40:** Lower bound of Caution classification (e.g., young domain + missing email authentication + HTTP).
* **Score = 39:** Upper bound of Dangerous classification (e.g., brand token in domain with login term or critical finding clamp).
* **Score = 0:** Maximum risk accumulation (malicious threat feed match + deceptive login form + credential harvesting).
