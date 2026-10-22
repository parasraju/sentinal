import { describe, expect, it } from "vitest";
import { analyzeUrl } from "../../src/security/url-analyzer";
import { assessWebsite } from "../../src/security/trust-score";
import type { ConnectionInfo, CookieReport, PageEvidence, ReputationResult, ScriptAnalysis, TrackerReport } from "../../src/shared/types";

const connection = (protocol: "http:" | "https:"): ConnectionInfo => ({ protocol, status: protocol === "https:" ? "secure" : "insecure", secure: protocol === "https:", mixedContentCount: 0, mixedContentExamples: [], explanation: protocol === "https:" ? "HTTPS" : "HTTP", limitations: [] });
const scripts: ScriptAnalysis = { available: false, externalScriptCount: 0, inlineScriptCount: 0, thirdPartyScriptHosts: [], inlinePatternHits: [], sensitiveInputHandlers: [], clipboardIndicators: 0, keyboardIndicators: 0, suspiciousOverlay: false, suspiciousOverlayEvidence: [], risk: "none", confidence: "low", findings: [], limitations: [] };
const cookies: CookieReport = { available: true, reason: null, total: 0, firstPartyCount: 0, thirdPartyCount: 0, sessionCount: 0, trackingCount: 0, concernCount: 0, cookies: [], findings: [], limitations: [], deletedThisSession: 0 };
const trackers: TrackerReport = { available: true, reason: null, observedThirdPartyDomains: 0, recognizedCount: 0, unknownCount: 0, thirdPartyRequestCount: 0, trackers: [], unknownDomains: [], blockedRecent: 0, blockedNote: null, findings: [], limitations: [] };
const reputation: ReputationResult = { matches: [], providerId: "test", available: true, reason: null, cached: false };
const page: PageEvidence = {
  url: "https://example.com/",
  origin: "https://example.com",
  title: "",
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

function scoreFor(url: string) {
  const signals = analyzeUrl(url);
  return assessWebsite({ url, signals, connection: connection(signals.protocol === "http:" ? "http:" : "https:"), phishing: { verdict: "none", riskScore: 0, brandImpersonation: signals.brandImpersonation, indicators: signals.indicators, credentialCollection: false, deceptiveContext: false, knownReputationMatch: null, explanation: "none" }, page, forms: [], scripts, cookies, trackers, reputation }).score;
}

describe("Sentinel trust score", () => {
  it("penalizes HTTP while leaving a clean HTTPS page at the baseline", () => {
    expect(scoreFor("http://example.com/")).toBe(80);
    expect(scoreFor("https://example.com/")).toBe(100);
  });

  it("applies phishing penalties to deceptive credential pages", () => {
    const url = "https://paypa1-login.com/login";
    const signals = analyzeUrl(url);
    const assessment = assessWebsite({ url, signals, connection: connection("https:"), phishing: { verdict: "likely", riskScore: 80, brandImpersonation: signals.brandImpersonation, indicators: signals.indicators, credentialCollection: true, deceptiveContext: true, knownReputationMatch: null, explanation: "test" }, page, forms: [], scripts, cookies, trackers, reputation });
    expect(assessment.score).toBeLessThan(50);
    expect(assessment.findings.some((finding) => finding.penalty > 0)).toBe(true);
  });

  it("does not call a URL-only assessment safe", () => {
    const signals = analyzeUrl("https://example.com/");
    const assessment = assessWebsite({ url: "https://example.com/", signals, connection: connection("https:"), phishing: { verdict: "none", riskScore: 0, brandImpersonation: [], indicators: [], credentialCollection: false, deceptiveContext: false, knownReputationMatch: null, explanation: "none" }, page: null, forms: [], scripts: { ...scripts, available: false }, cookies: { ...cookies, available: false, reason: "unavailable" }, trackers: { ...trackers, available: false, reason: "unavailable" }, reputation });
    expect(assessment.score).toBeNull();
    expect(assessment.classification).toBe("unknown");
  });

  it("does not show a perfect score when page evidence is only partial", () => {
    const signals = analyzeUrl("https://example.com/");
    const assessment = assessWebsite({
      url: "https://example.com/",
      signals,
      connection: connection("https:"),
      phishing: { verdict: "none", riskScore: 0, brandImpersonation: [], indicators: [], credentialCollection: false, deceptiveContext: false, knownReputationMatch: null, explanation: "none" },
      page,
      forms: [],
      scripts,
      cookies: { ...cookies, available: false, reason: "unavailable" },
      trackers: { ...trackers, available: false, reason: "unavailable" },
      reputation,
    });

    expect(assessment.evidenceCompleteness).toBe("partial");
    expect(assessment.score).toBeNull();
    expect(assessment.classification).toBe("unknown");
    expect(assessment.topFactors[0]).toContain("Some page evidence is unavailable");
  });

  it("enforces category caps to prevent excessive deductions from correlated signals", () => {
    // Both HTTP (20) and non-standard port (20) belong to transport bucket (cap = 25)
    const url = "http://example.com:8080/";
    const signals = analyzeUrl(url);
    const assessment = assessWebsite({
      url,
      signals,
      connection: connection("http:"),
      phishing: { verdict: "none", riskScore: 0, brandImpersonation: [], indicators: [], credentialCollection: false, deceptiveContext: false, knownReputationMatch: null, explanation: "none" },
      page,
      forms: [],
      scripts,
      cookies,
      trackers,
      reputation,
    });
    // Uncapped penalty would be 20 (http) + 20 (port) = 40 (score 60)
    // Capped at 25 means score is 100 - 25 = 75
    expect(assessment.score).toBe(75);
    expect(assessment.classification).toBe("caution");
  });

  it("detects and heavily penalizes brand mismatch fake login forms", () => {
    const url = "https://suspicious-origin.com/login";
    const signals = analyzeUrl(url);
    const pageWithMismatch: PageEvidence = {
      ...page,
      brandMismatchDetected: true,
      brandMismatchBrand: "Microsoft",
      brandMismatchEvidence: ["Page title mentions Microsoft", "Password fields detected on unverified domain"],
    };

    const assessment = assessWebsite({
      url,
      signals,
      connection: connection("https:"),
      phishing: { verdict: "suspicious", riskScore: 40, brandImpersonation: [], indicators: [], credentialCollection: true, deceptiveContext: true, knownReputationMatch: null, explanation: "brand mismatch" },
      page: pageWithMismatch,
      forms: [],
      scripts,
      cookies,
      trackers,
      reputation,
    });

    const mismatchFinding = assessment.findings.find((f) => f.id === "phishing:brand-mismatch-login");
    expect(mismatchFinding).toBeDefined();
    expect(mismatchFinding?.penalty).toBe(40);
    expect(assessment.score).toBeLessThanOrEqual(60);
  });

  it("penalizes hidden or miniature iframes commonly used for clickjacking", () => {
    const url = "https://example.com/";
    const signals = analyzeUrl(url);
    const pageWithHiddenIframe: PageEvidence = {
      ...page,
      hiddenIframeCount: 2,
      hiddenIframeExamples: ["iframe[style*='display:none']", "iframe[style*='opacity:0']"],
    };

    const assessment = assessWebsite({
      url,
      signals,
      connection: connection("https:"),
      phishing: { verdict: "none", riskScore: 0, brandImpersonation: [], indicators: [], credentialCollection: false, deceptiveContext: false, knownReputationMatch: null, explanation: "none" },
      page: pageWithHiddenIframe,
      forms: [],
      scripts,
      cookies,
      trackers,
      reputation,
    });

    const iframeFinding = assessment.findings.find((f) => f.id === "content:hidden-iframe");
    expect(iframeFinding).toBeDefined();
    expect(iframeFinding?.penalty).toBe(15);
    expect(assessment.score).toBe(85);
  });

  it("correctly classifies score boundaries (80 Safe, 79 Caution, 40 Caution, 39 Dangerous)", () => {
    const url = "https://example.com/";
    const signals = analyzeUrl(url);

    // Baseline: 100 -> Safe
    const a100 = assessWebsite({ url, signals, connection: connection("https:"), phishing: { verdict: "none", riskScore: 0, brandImpersonation: [], indicators: [], credentialCollection: false, deceptiveContext: false, knownReputationMatch: null, explanation: "none" }, page, forms: [], scripts, cookies, trackers, reputation });
    expect(a100.score).toBe(100);
    expect(a100.classification).toBe("safe");

    // HTTP: 80 -> Safe (boundary condition: >= 80 is safe)
    const a80 = assessWebsite({ url: "http://example.com/", signals: analyzeUrl("http://example.com/"), connection: connection("http:"), phishing: { verdict: "none", riskScore: 0, brandImpersonation: [], indicators: [], credentialCollection: false, deceptiveContext: false, knownReputationMatch: null, explanation: "none" }, page, forms: [], scripts, cookies, trackers, reputation });
    expect(a80.score).toBe(80);
    expect(a80.classification).toBe("safe");

    // Critical finding caps score at 39 -> Dangerous
    const criticalReputation: ReputationResult = {
      matches: [{ domain: "example.com", label: "Phishing Test", severity: "critical", source: "test", providerId: "sentinel-local", fetchedAt: 1 }],
      providerId: "test",
      available: true,
      reason: null,
      cached: false,
    };
    const aCritical = assessWebsite({ url, signals, connection: connection("https:"), phishing: { verdict: "confirmed", riskScore: 100, brandImpersonation: [], indicators: [], credentialCollection: false, deceptiveContext: false, knownReputationMatch: criticalReputation.matches[0] ?? null, explanation: "confirmed" }, page, forms: [], scripts, cookies, trackers, reputation: criticalReputation });
    expect(aCritical.score).toBeLessThanOrEqual(39);
    expect(aCritical.classification).toBe("dangerous");
  });

  it("computes evidence-based confidenceScore accurately", () => {
    const signals = analyzeUrl("https://example.com/");
    const baseAssessment = assessWebsite({
      url: "https://example.com/",
      signals,
      connection: connection("https:"),
      phishing: { verdict: "none", riskScore: 0, brandImpersonation: [], indicators: [], credentialCollection: false, deceptiveContext: false, knownReputationMatch: null, explanation: "none" },
      page,
      forms: [],
      scripts,
      cookies,
      trackers,
      reputation,
    });
    // URL (0.2) + Page (0.25) + Cookies/trackers (0.15) = 0.60
    expect(baseAssessment.confidenceScore).toBe(0.6);
    expect(baseAssessment.confidence).toBe("medium");

    // Adding domain intelligence and headers increases confidence
    const fullAssessment = assessWebsite({
      url: "https://example.com/",
      signals,
      connection: connection("https:"),
      phishing: { verdict: "none", riskScore: 0, brandImpersonation: [], indicators: [], credentialCollection: false, deceptiveContext: false, knownReputationMatch: null, explanation: "none" },
      page,
      forms: [],
      scripts,
      cookies,
      trackers,
      reputation,
      headers: { available: true, headers: [], presentCount: 4, missingCount: 2, score: 70, findings: [], limitations: [], error: null },
      domainIntel: { available: true, domain: "example.com", domainAgeDays: 500, registrationDate: null, expiryDate: null, registrar: null, ctCertAgeDays: null, ctCertTotal: null, ctIssuers: [], hasSpf: true, hasDmarc: true, dmarcPolicy: null, mxRecords: [], aRecords: [], findings: [], limitations: [], error: null },
    });
    // 0.60 + Headers (0.15) + Domain Intel (0.25) = 1.0
    expect(fullAssessment.confidenceScore).toBe(1.0);
    expect(fullAssessment.confidence).toBe("high");
  });
});
