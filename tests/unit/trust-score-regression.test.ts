import { describe, expect, it } from "vitest";
import { generateReport } from "../../src/reports/report-generator";
import { analyzeConnection } from "../../src/security/connection-analyzer";
import { analyzeUrl } from "../../src/security/url-analyzer";
import { assessWebsite } from "../../src/security/trust-score";
import type {
  CookieReport,
  PageEvidence,
  ReputationResult,
  ScriptAnalysis,
  TabSnapshot,
  TrackerReport,
} from "../../src/shared/types";

const scripts: ScriptAnalysis = {
  available: false,
  externalScriptCount: 0,
  inlineScriptCount: 0,
  thirdPartyScriptHosts: [],
  inlinePatternHits: [],
  sensitiveInputHandlers: [],
  clipboardIndicators: 0,
  keyboardIndicators: 0,
  suspiciousOverlay: false,
  suspiciousOverlayEvidence: [],
  risk: "none",
  confidence: "low",
  findings: [],
  limitations: [],
};

const cookies = (available = true): CookieReport => ({
  available,
  reason: available ? null : "Cookie metadata unavailable",
  total: 0,
  firstPartyCount: 0,
  thirdPartyCount: 0,
  sessionCount: 0,
  trackingCount: 0,
  concernCount: 0,
  cookies: [],
  findings: [],
  limitations: [],
  deletedThisSession: 0,
});

const trackers = (available = true): TrackerReport => ({
  available,
  reason: available ? null : "Third-party request evidence unavailable",
  observedThirdPartyDomains: 0,
  recognizedCount: 0,
  unknownCount: 0,
  thirdPartyRequestCount: 0,
  trackers: [],
  unknownDomains: [],
  blockedRecent: 0,
  blockedNote: null,
  findings: [],
  limitations: [],
});

const reputation: ReputationResult = {
  matches: [],
  providerId: "test",
  available: true,
  reason: null,
  cached: false,
};

const page: PageEvidence = {
  url: "https://example.com/",
  origin: "https://example.com",
  title: "Example",
  isTopFrame: true,
  collectedAt: 1,
  forms: [],
  scripts: [],
  resources: [],
  mixedContentCount: 0,
  mixedContentExamples: [],
  sensitiveInputCount: 0,
  passwordFieldCount: 0,
  sensitiveInputHandlers: [],
  clipboardHandlerIndicators: [],
  suspiciousOverlay: false,
  suspiciousOverlayEvidence: [],
  iframeCount: 0,
  hiddenIframeCount: 0,
  hiddenIframeExamples: [],
  brandMismatchDetected: false,
  brandMismatchBrand: null,
  brandMismatchEvidence: [],
  limitations: [],
};

function assess(url: string, options: { page?: PageEvidence | null; cookies?: CookieReport; trackers?: TrackerReport } = {}) {
  const signals = analyzeUrl(url);
  const connection = analyzeConnection(url, options.page ?? page, true);
  return assessWebsite({
    url,
    signals,
    connection,
    phishing: {
      verdict: "none",
      riskScore: 0,
      brandImpersonation: signals.brandImpersonation,
      indicators: signals.indicators,
      credentialCollection: false,
      deceptiveContext: false,
      knownReputationMatch: null,
      explanation: "none",
    },
    page: options.page === undefined ? page : options.page,
    forms: [],
    scripts,
    cookies: options.cookies ?? cookies(),
    trackers: options.trackers ?? trackers(),
    reputation,
    now: 1,
  });
}

function snapshot(assessment: ReturnType<typeof assess>): TabSnapshot {
  return {
    tabId: 7,
    url: "https://example.com/",
    domain: assessment.domain,
    title: "Example",
    fetchedAt: 1,
    assessment,
    connection: analyzeConnection("https://example.com/", page, true),
    forms: [],
    scripts,
    cookies: cookies(),
    trackers: trackers(),
    protection: { enabledRulesets: [], dynamicAllowRules: 0, mode: "standard", blockingActive: true, allowlisted: false, lastSyncedAt: null, error: null },
    permissions: { cookies: true, hostAccess: true, contentScript: true, dnrFeedback: true, message: null },
    allowlisted: false,
    evidence: page,
    pageEvidenceAvailable: true,
  };
}

describe("reported trust-score regression coverage", () => {
  it("keeps HTTP below clean HTTPS while preserving deterministic evidence completeness", () => {
    const http = assess("http://example.com/");
    const https = assess("https://example.com/");

    expect(http.score).toBe(80);
    expect(http.classification).toBe("safe");
    expect(http.evidenceCompleteness).toBe("full");
    expect(https.score).toBe(100);
    expect(https.classification).toBe("safe");
    expect(https.evidenceCompleteness).toBe("full");
  });

  it("does not assign a numeric score when all page-level evidence is unavailable", () => {
    const assessment = assess("https://example.com/", {
      page: null,
      cookies: cookies(false),
      trackers: trackers(false),
    });

    expect(assessment.score).toBeNull();
    expect(assessment.classification).toBe("unknown");
    expect(assessment.evidenceCompleteness).toBe("url-only");
    expect(assessment.topFactors[0]).toContain("cannot produce a reliable numeric score");
  });

  it("keeps suspicious-domain indicators visible and penalized without treating HTTPS as proof of safety", () => {
    const url = "https://https-secure-paypa1-login.example/verify";
    const signals = analyzeUrl(url);
    const assessment = assessWebsite({
      url,
      signals,
      connection: analyzeConnection(url, page, true),
      phishing: {
        verdict: "suspicious",
        riskScore: 40,
        brandImpersonation: signals.brandImpersonation,
        indicators: signals.indicators,
        credentialCollection: false,
        deceptiveContext: false,
        knownReputationMatch: null,
        explanation: "suspicious URL indicators",
      },
      page,
      forms: [],
      scripts,
      cookies: cookies(),
      trackers: trackers(),
      reputation,
      now: 1,
    });

    expect(assessment.score).toBeLessThan(100);
    expect(assessment.findings.some((finding) => finding.penalty > 0)).toBe(true);
    expect(assessment.findings.some((finding) => finding.id.startsWith("phishing:") || finding.id === "domain:brand-impersonation")).toBe(true);
  });

  it("propagates the computed snapshot score into generated reports", () => {
    const assessment = assess("http://example.com/");
    const report = generateReport(snapshot(assessment), 2);

    expect(assessment.score).toBe(80);
    expect(report.assessment.score).toBe(assessment.score);
    expect(report.assessment.classification).toBe(assessment.classification);
    expect(report.assessment.evidenceCompleteness).toBe(assessment.evidenceCompleteness);
  });
});
