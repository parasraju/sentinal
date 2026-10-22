import { PENALTIES } from "../shared/constants";
import type { SecurityHeaderItem, SecurityHeadersReport, SecurityFinding } from "../shared/types";

export interface HeaderAnalyzerOptions {
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

const HEADER_DEFINITIONS: Array<{
  name: string;
  label: string;
  weight: number;
  critical: boolean;
  explanation: string;
}> = [
  {
    name: "strict-transport-security",
    label: "HSTS",
    weight: 25,
    critical: true,
    explanation: "Forces browsers to use HTTPS for future requests, protecting against downgrade attacks.",
  },
  {
    name: "content-security-policy",
    label: "CSP",
    weight: 25,
    critical: true,
    explanation: "Restricts sources from which scripts, styles, and other resources can be loaded to prevent XSS.",
  },
  {
    name: "x-frame-options",
    label: "X-Frame-Options",
    weight: 15,
    critical: false,
    explanation: "Prevents the page from being rendered inside an iframe, stopping clickjacking.",
  },
  {
    name: "x-content-type-options",
    label: "X-Content-Type-Options",
    weight: 15,
    critical: false,
    explanation: "Instructs browsers not to sniff MIME types, mitigating MIME confusion attacks.",
  },
  {
    name: "referrer-policy",
    label: "Referrer-Policy",
    weight: 10,
    critical: false,
    explanation: "Controls how much referrer information is included with requests made from this page.",
  },
  {
    name: "permissions-policy",
    label: "Permissions-Policy",
    weight: 10,
    critical: false,
    explanation: "Explicitly delegates browser features and APIs (camera, microphone, geolocation).",
  },
];

export async function analyzeSecurityHeaders(
  url: string,
  options: HeaderAnalyzerOptions = {},
): Promise<SecurityHeadersReport> {
  const timeoutMs = options.timeoutMs ?? 4000;
  const fetchFn = options.fetchFn ?? globalThis.fetch;

  const emptyReport: SecurityHeadersReport = {
    available: false,
    headers: [],
    presentCount: 0,
    missingCount: 0,
    score: 0,
    findings: [],
    limitations: [
      "Security headers are server configuration signals. Missing headers indicate security posture, not proof of fraud.",
      "Extensions inspect headers via non-invasive HEAD requests; content bodies are never read.",
    ],
    error: null,
  };

  if (!url || !fetchFn || (!url.startsWith("http://") && !url.startsWith("https://"))) {
    return emptyReport;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchFn(url, {
      method: "HEAD",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const items: SecurityHeaderItem[] = [];
    let earnedWeight = 0;
    const totalWeight = HEADER_DEFINITIONS.reduce((sum, def) => sum + def.weight, 0);

    for (const def of HEADER_DEFINITIONS) {
      const headerVal = response.headers.get(def.name);
      const present = Boolean(headerVal);
      if (present) earnedWeight += def.weight;

      items.push({
        name: def.name,
        label: def.label,
        value: headerVal,
        present,
        critical: def.critical,
        explanation: def.explanation,
      });
    }

    const presentCount = items.filter((item) => item.present).length;
    const missingCount = items.length - presentCount;
    const score = Math.round((earnedWeight / totalWeight) * 100);

    const findings: SecurityFinding[] = [];
    const missingHsts = !items.find((i) => i.name === "strict-transport-security")?.present;
    const missingCsp = !items.find((i) => i.name === "content-security-policy")?.present;
    const isHttps = url.startsWith("https://");

    if (isHttps && missingHsts && missingCsp) {
      findings.push({
        id: "header:missing-critical-posture",
        category: "header",
        severity: "low",
        confidence: "high",
        title: "Missing HSTS and Content Security Policy headers",
        explanation:
          "The website does not enforce HTTP Strict Transport Security (HSTS) or Content Security Policy (CSP). While common on non-financial sites, these headers are recommended to prevent downgrade attacks and script injection.",
        evidence: ["HSTS: Missing", "CSP: Missing", `Audited headers score: ${score}/100`],
        remediation: "Verify the site identity if performing transactions.",
        source: "observed",
        penalty: PENALTIES.missingHstsAndCsp,
      });
    } else if (missingCount > 3) {
      findings.push({
        id: "header:suboptimal-posture",
        category: "header",
        severity: "info",
        confidence: "medium",
        title: "Suboptimal HTTP security header configuration",
        explanation: `The server does not include ${missingCount} recommended security headers (${items.filter((i) => !i.present).map((i) => i.label).join(", ")}). This is a server configuration observation.`,
        evidence: items.filter((i) => !i.present).map((i) => `${i.label} (${i.name}) missing`),
        remediation: "No immediate user action required.",
        source: "observed",
        penalty: PENALTIES.missingSecurityHeaders,
      });
    } else if (score >= 80) {
      findings.push({
        id: "header:strong-posture",
        category: "header",
        severity: "info",
        confidence: "high",
        title: "Strong HTTP security header deployment",
        explanation:
          "The website deploys modern transport security, content security policy, and anti-framing headers.",
        evidence: items.filter((i) => i.present).map((i) => `${i.label}: Active`),
        remediation: "Good security posture observed.",
        source: "observed",
        penalty: 0,
      });
    }

    return {
      available: true,
      headers: items,
      presentCount,
      missingCount,
      score,
      findings,
      limitations: emptyReport.limitations,
      error: null,
    };
  } catch (err) {
    clearTimeout(timeoutId);
    return {
      ...emptyReport,
      error: err instanceof Error ? err.message : "HEAD request failed or timed out",
    };
  }
}
