import type { SentinelReport, ReportRecommendation } from "./report-types";
import type { TabSnapshot } from "../shared/types";
import { sanitizeText } from "../shared/validation";

const REPORT_VERSION = "1.0.0";

function uniq(items: string[]): string[] {
  return Array.from(new Set(items.filter(Boolean)));
}

function buildRecommendations(snapshot: TabSnapshot): ReportRecommendation[] {
  const recommendations: ReportRecommendation[] = [];
  const findings = snapshot.assessment.findings;
  const has = (id: string) => findings.some((finding) => finding.id === id && finding.penalty >= 0);
  const critical = snapshot.assessment.critical;

  if (critical) {
    recommendations.push({
      priority: "high",
      action: "Leave this site now and do not enter any information.",
      reason: "High-confidence phishing or known-bad evidence was observed. Sentinel cannot make this page safe.",
    });
  }

  if (has("phishing:credential-collection") || has("form:external-sensitive")) {
    recommendations.push({
      priority: "high",
      action: "Do not enter passwords, one-time codes, card numbers, or identity numbers on this page.",
      reason:
        "Sensitive fields are present alongside deceptive-domain or unrelated external form-destination evidence.",
    });
  }

  if (has("connection:http")) {
    recommendations.push({
      priority: "medium",
      action: "Avoid submitting sensitive data over this HTTP connection.",
      reason: "Traffic to and from this page is not encrypted.",
    });
  }

  if (has("tracker:significant-activity")) {
    recommendations.push({
      priority: "medium",
      action: "Enable standard tracker blocking for this browser.",
      reason: "Multiple known tracking domains were observed contacting this page.",
    });
  }

  if (snapshot.cookies.available && snapshot.cookies.trackingCount > 0) {
    recommendations.push({
      priority: "low",
      action: "Review and remove tracking-related cookies from the Cookie Manager.",
      reason: `${snapshot.cookies.trackingCount} cookie${snapshot.cookies.trackingCount === 1 ? "" : "s"} appear tracking-related. Removing them may sign you out or reset preferences.`,
    });
  }

  if (has("form:external-account") || has("form:action-changed")) {
    recommendations.push({
      priority: "medium",
      action: "Verify the form destination through an independently obtained official address.",
      reason: "A form sends data outside this origin or its destination changed after load.",
    });
  }

  if (snapshot.assessment.classification === "safe" && recommendations.length === 0) {
    recommendations.push({
      priority: "low",
      action: "Continue normally, but keep checking the address before entering credentials.",
      reason: "No material risk indicators were observed in the evidence available to Sentinel.",
    });
  }

  if (!snapshot.cookies.available) {
    recommendations.push({
      priority: "low",
      action: "Reload the page or grant cookie access if you want cookie inspection.",
      reason: "Cookie metadata was unavailable, so cookie risk is unknown rather than safe.",
    });
  }

  const order = { high: 0, medium: 1, low: 2 } as const;
  return recommendations.sort((a, b) => order[a.priority] - order[b.priority]).slice(0, 6);
}

export function generateReport(snapshot: TabSnapshot, generatedAt = Date.now()): SentinelReport {
  const assessment = snapshot.assessment;
  const cookieConcerns = snapshot.cookies.cookies
    .filter((cookie) => cookie.concerns.length > 0)
    .slice(0, 50)
    .map((cookie) => ({
      name: sanitizeText(cookie.name, 120),
      domain: sanitizeText(cookie.domain, 200),
      concerns: cookie.concerns.map((concern) => sanitizeText(concern, 300)),
    }));

  const trackingCookies = snapshot.cookies.cookies
    .filter((cookie) => cookie.purposes.includes("tracking"))
    .slice(0, 50)
    .map((cookie) => ({
      name: sanitizeText(cookie.name, 120),
      domain: sanitizeText(cookie.domain, 200),
      persistentDays:
        cookie.expirationDate !== null
          ? Math.max(0, Math.round((cookie.expirationDate - generatedAt / 1000) / 86400))
          : null,
    }));

  return {
    reportVersion: REPORT_VERSION,
    generatedAt,
    disclaimer:
      "This report covers observable evidence only. A favorable score is not a guarantee that a website is safe. Sentinel does not read, store, or transmit passwords, form values, one-time codes, card numbers, or clipboard contents.",
    assessment: {
      domain: assessment.domain,
      score: assessment.score,
      classification: assessment.classification,
      confidence: assessment.confidence,
      critical: assessment.critical,
      assessedAt: assessment.assessedAt,
      evidenceCompleteness: assessment.evidenceCompleteness,
      topFactors: assessment.topFactors.map((factor) => sanitizeText(factor, 200)),
    },
    connection: {
      protocol: snapshot.connection.protocol,
      status: snapshot.connection.status,
      secure: snapshot.connection.secure,
      mixedContentCount: snapshot.connection.mixedContentCount,
      explanation: sanitizeText(snapshot.connection.explanation, 400),
    },
    trackers: {
      available: snapshot.trackers.available,
      observedThirdPartyDomains: snapshot.trackers.observedThirdPartyDomains,
      recognizedCount: snapshot.trackers.recognizedCount,
      unknownCount: snapshot.trackers.unknownCount,
      thirdPartyRequestCount: snapshot.trackers.thirdPartyRequestCount,
      blockedRecent: snapshot.trackers.blockedRecent,
      services: snapshot.trackers.trackers.slice(0, 100).map((tracker) => ({
        domain: sanitizeText(tracker.domain, 200),
        company: tracker.company ? sanitizeText(tracker.company, 100) : null,
        category: tracker.category,
        requests: tracker.requests,
        recognized: tracker.recognized,
      })),
      unknownDomains: snapshot.trackers.unknownDomains.slice(0, 50).map((item) => ({
        domain: sanitizeText(item.domain, 200),
        requests: item.requests,
      })),
    },
    cookies: {
      available: snapshot.cookies.available,
      reason: snapshot.cookies.reason ? sanitizeText(snapshot.cookies.reason, 300) : null,
      total: snapshot.cookies.total,
      firstPartyCount: snapshot.cookies.firstPartyCount,
      thirdPartyCount: snapshot.cookies.thirdPartyCount,
      sessionCount: snapshot.cookies.sessionCount,
      trackingCount: snapshot.cookies.trackingCount,
      concernCount: snapshot.cookies.concernCount,
      deletedThisSession: snapshot.cookies.deletedThisSession,
      concerns: cookieConcerns,
      tracking: trackingCookies,
    },
    forms: {
      total: snapshot.forms.length,
      sensitive: snapshot.forms.filter((form) => form.sensitiveKinds.length > 0).length,
      destinations: snapshot.forms.slice(0, 30).map((form) => ({
        host: form.destinationHost ? sanitizeText(form.destinationHost, 200) : null,
        relationship: form.relationship,
        risk: form.risk,
        trustedProvider: form.trustedProvider ? sanitizeText(form.trustedProvider, 100) : null,
        sensitiveKinds: form.sensitiveKinds,
        flags: form.flags,
      })),
    },
    scripts: {
      available: snapshot.scripts.available,
      externalScriptCount: snapshot.scripts.externalScriptCount,
      inlineScriptCount: snapshot.scripts.inlineScriptCount,
      thirdPartyScriptHosts: snapshot.scripts.thirdPartyScriptHosts.slice(0, 50).map((host) => sanitizeText(host, 200)),
      risk: snapshot.scripts.risk,
      signals: snapshot.scripts.inlinePatternHits.slice(0, 20).map((hit) => ({
        label: sanitizeText(hit.label, 120),
        count: hit.count,
        confidence: hit.confidence,
      })),
    },
    findings: assessment.findings.slice(0, 60).map((finding) => ({
      id: sanitizeText(finding.id, 120),
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      title: sanitizeText(finding.title, 200),
      explanation: sanitizeText(finding.explanation, 600),
      evidence: finding.evidence.slice(0, 10).map((evidence) => sanitizeText(evidence, 300)),
      remediation: sanitizeText(finding.remediation, 400),
      penalty: finding.penalty,
    })),
    protection: {
      mode: snapshot.protection.mode,
      blockingActive: snapshot.protection.blockingActive,
      enabledRulesets: snapshot.protection.enabledRulesets.slice(0, 10),
      allowlisted: snapshot.protection.allowlisted,
      error: snapshot.protection.error ? sanitizeText(snapshot.protection.error, 300) : null,
    },
    recommendations: buildRecommendations(snapshot),
    limitations: uniq([
      ...assessment.limitations,
      "Detection is limited to evidence the extension can observe: URL structure, DOM metadata, cookies exposed by the browser, and resource timing entries.",
      "Sentinel does not independently validate TLS certificates; Chromium's own validation is authoritative.",
      "No report field contains passwords, one-time codes, card numbers, form values, clipboard contents, or authentication tokens.",
    ]).slice(0, 16),
  };
}

/* ------------------------------ export safety ----------------------------- */

const DENY_KEYS = new Set([
  "password",
  "passwd",
  "secret",
  "authorization",
  "cookievalue",
  "value",
  "otp",
  "cardnumber",
  "ssn",
  "token",
  "accesstoken",
  "refreshtoken",
]);

function sanitizeString(input: string): string {
  let value = sanitizeText(input, 1000).replace(
    /\b(https?:\/\/)([^/\s@]+@)?([^/\s?#]+)([^\s?#]*)(\?[^\s#]*)?(#\S*)?/gi,
    (_match, scheme: string, _user: string, host: string, path: string) =>
      `${scheme}${host}${path}`,
  );
  value = value.replace(/([?&](?:token|key|secret|password|code|auth|session)=)[^&\s]+/gi, "$1[redacted]");
  return sanitizeText(value, 1000);
}

/** Defensive recursive sanitizer used immediately before download. */
export function sanitizeForExport(input: unknown, depth = 0): unknown {
  if (depth > 8) return null;
  if (typeof input === "string") return sanitizeString(input);
  if (typeof input === "number") return Number.isFinite(input) ? input : null;
  if (typeof input === "boolean" || input === null) return input;
  if (Array.isArray(input)) {
    return input.slice(0, 200).map((item) => sanitizeForExport(item, depth + 1));
  }
  if (typeof input === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      if (DENY_KEYS.has(key.toLowerCase())) continue;
      output[key] = sanitizeForExport(value, depth + 1);
    }
    return output;
  }
  return null;
}

export function buildExportPayload(report: SentinelReport): string {
  const sanitized = sanitizeForExport({ format: "sentinel-report", report }) as {
    format: "sentinel-report";
    report: SentinelReport;
  };
  return JSON.stringify(sanitized, null, 2);
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function buildHtmlReport(report: SentinelReport): string {
  const rows = (items: string[]): string =>
    items.length === 0
      ? "<p class=\"muted\">None observed.</p>"
      : `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;

  const findingRows = report.findings
    .map(
      (finding) => `
      <tr>
        <td><span class="sev sev-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
        <td><strong>${escapeHtml(finding.title)}</strong><br /><span class="muted">${escapeHtml(finding.explanation)}</span>
        ${finding.evidence.length ? `<br /><span class="mono">${escapeHtml(finding.evidence.join(" · "))}</span>` : ""}</td>
      </tr>`,
    )
    .join("");

  const recommendationRows = report.recommendations
    .map(
      (recommendation) => `
      <li><strong>${escapeHtml(recommendation.priority.toUpperCase())}</strong> — ${escapeHtml(recommendation.action)}
      <br /><span class="muted">${escapeHtml(recommendation.reason)}</span></li>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sentinel report — ${escapeHtml(report.assessment.domain)}</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; background: #0b1220; color: #e8effa; font-family: ui-sans-serif, system-ui, sans-serif; line-height: 1.55; }
  main { max-width: 840px; margin: 0 auto; padding: 40px 24px 80px; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  h2 { font-size: 15px; text-transform: uppercase; letter-spacing: .12em; color: #9fb2cf; margin: 32px 0 10px; }
  .score { font-size: 56px; font-weight: 800; margin: 12px 0 0; }
  .muted { color: #9fb2cf; }
  .mono { font-family: ui-monospace, monospace; font-size: 12px; color: #c9d6ea; }
  .card { border: 1px solid #1f3152; background: #0e1728; border-radius: 14px; padding: 18px; }
  table { width: 100%; border-collapse: collapse; }
  td { border-top: 1px solid #1f3152; padding: 10px 8px; vertical-align: top; font-size: 13px; }
  ul { padding-left: 20px; }
  li { margin: 6px 0; font-size: 13px; }
  .sev { font-size: 10px; text-transform: uppercase; letter-spacing: .08em; padding: 3px 7px; border-radius: 999px; border: 1px solid #2b3d5e; }
  .sev-critical, .sev-high { color: #f87171; border-color: #7f1d1d; }
  .sev-medium { color: #fbbf24; border-color: #78350f; }
  .sev-low, .sev-info { color: #9fb2cf; }
  .notice { border-left: 3px solid #2dd4bf; padding-left: 12px; font-size: 13px; color: #c9d6ea; }
</style>
</head>
<body>
<main>
  <h1>Sentinel Privacy Report</h1>
  <p class="muted">${escapeHtml(report.assessment.domain)} · Generated ${escapeHtml(new Date(report.generatedAt).toLocaleString())}</p>
  <div class="card">
    <p class="score">${report.assessment.score === null ? "—" : escapeHtml(String(report.assessment.score))}<span style="font-size:16px;color:#9fb2cf"> / 100</span></p>
    <p><strong>${escapeHtml(report.assessment.classification)}</strong> · Confidence ${escapeHtml(report.assessment.confidence)}
    · Evidence ${escapeHtml(report.assessment.evidenceCompleteness)}</p>
    ${rows(report.assessment.topFactors)}
  </div>

  <h2>Connection</h2>
  <div class="card"><p>${escapeHtml(report.connection.explanation)}</p>
  <p class="muted">Mixed-content resources observed: ${escapeHtml(String(report.connection.mixedContentCount))}</p></div>

  <h2>Trackers</h2>
  <div class="card">
    <p>${escapeHtml(String(report.trackers.recognizedCount))} recognized tracking domains · ${escapeHtml(String(report.trackers.unknownCount))} unknown third-party domains · ${escapeHtml(String(report.trackers.thirdPartyRequestCount))} third-party requests</p>
    ${rows(report.trackers.services.map((service) => `${service.company ?? "Unknown"} — ${service.domain} (${service.category}, ${service.requests} request(s))`))}
  </div>

  <h2>Cookies</h2>
  <div class="card">
    <p>${escapeHtml(String(report.cookies.total))} cookies · ${escapeHtml(String(report.cookies.concernCount))} with concerns · ${escapeHtml(String(report.cookies.trackingCount))} tracking-related · ${escapeHtml(String(report.cookies.sessionCount))} session-related</p>
    ${rows(report.cookies.concerns.map((cookie) => `${cookie.name} (${cookie.domain}): ${cookie.concerns.join(" ")}`))}
    ${report.cookies.available ? "" : `<p class="muted">${escapeHtml(report.cookies.reason ?? "Cookie data unavailable.")}</p>`}
  </div>

  <h2>Forms and scripts</h2>
  <div class="card">
    <p>${escapeHtml(String(report.forms.total))} forms observed · ${escapeHtml(String(report.forms.sensitive))} contain sensitive fields · Script risk: ${escapeHtml(report.scripts.risk)}</p>
    ${rows(report.forms.destinations.map((form) => `${form.host ?? "unknown destination"} — ${form.relationship}, ${form.risk}${form.trustedProvider ? `, provider: ${form.trustedProvider}` : ""}`))}
    ${rows(report.scripts.signals.map((signal) => `${signal.label} ×${signal.count}`))}
  </div>

  <h2>Findings</h2>
  <div class="card"><table><tbody>${findingRows || "<tr><td>No findings.</td></tr>"}</tbody></table></div>

  <h2>Recommendations</h2>
  <div class="card"><ul>${recommendationRows}</ul></div>

  <h2>Limitations</h2>
  <div class="card"><ul>${report.limitations.map((limitation) => `<li>${escapeHtml(limitation)}</li>`).join("")}</ul></div>

  <h2>Disclaimer</h2>
  <p class="notice">${escapeHtml(report.disclaimer)}</p>
</main>
</body>
</html>`;
}
