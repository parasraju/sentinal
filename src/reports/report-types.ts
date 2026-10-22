import type {
  Classification,
  Confidence,
  FormFlag,
  ProtectionStatus,
  Severity,
  TrackerCategory,
} from "../shared/types";

export interface ReportRecommendation {
  priority: "high" | "medium" | "low";
  action: string;
  reason: string;
}

export interface SentinelReport {
  reportVersion: string;
  generatedAt: number;
  disclaimer: string;
  assessment: {
    domain: string;
    score: number | null;
    classification: Classification;
    confidence: Confidence;
    critical: boolean;
    assessedAt: number;
    evidenceCompleteness: string;
    topFactors: string[];
  };
  connection: {
    protocol: string;
    status: string;
    secure: boolean;
    mixedContentCount: number;
    explanation: string;
  };
  trackers: {
    available: boolean;
    observedThirdPartyDomains: number;
    recognizedCount: number;
    unknownCount: number;
    thirdPartyRequestCount: number;
    blockedRecent: number | null;
    services: {
      domain: string;
      company: string | null;
      category: TrackerCategory | "unknown";
      requests: number;
      recognized: boolean;
    }[];
    unknownDomains: { domain: string; requests: number }[];
  };
  cookies: {
    available: boolean;
    reason: string | null;
    total: number;
    firstPartyCount: number;
    thirdPartyCount: number;
    sessionCount: number;
    trackingCount: number;
    concernCount: number;
    deletedThisSession: number;
    concerns: { name: string; domain: string; concerns: string[] }[];
    tracking: { name: string; domain: string; persistentDays: number | null }[];
  };
  forms: {
    total: number;
    sensitive: number;
    destinations: {
      host: string | null;
      relationship: string;
      risk: string;
      trustedProvider: string | null;
      sensitiveKinds: string[];
      flags: FormFlag[];
    }[];
  };
  scripts: {
    available: boolean;
    externalScriptCount: number;
    inlineScriptCount: number;
    thirdPartyScriptHosts: string[];
    risk: string;
    signals: { label: string; count: number; confidence: Confidence }[];
  };
  findings: {
    id: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    title: string;
    explanation: string;
    evidence: string[];
    remediation: string;
    penalty: number;
  }[];
  protection: {
    mode: string;
    blockingActive: boolean;
    enabledRulesets: string[];
    allowlisted: boolean;
    error: string | null;
  };
  recommendations: ReportRecommendation[];
  limitations: string[];
}

export interface ExportPayload {
  format: "sentinel-report";
  report: SentinelReport;
}

export interface ProtectionSummaryInput {
  protection: ProtectionStatus;
}
