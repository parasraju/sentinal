import { SCORE_CAUTION_MIN, SCORE_SAFE_MIN } from "../shared/constants";
import type { Classification, Confidence, SecurityFinding, Severity } from "../shared/types";

const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const CONFIDENCE_ORDER: Record<Confidence, number> = {
  low: 0,
  medium: 1,
  high: 2,
};

export function classificationForScore(score: number | null): Classification {
  if (score === null || !Number.isFinite(score)) return "unknown";
  if (score >= SCORE_SAFE_MIN) return "safe";
  if (score >= SCORE_CAUTION_MIN) return "caution";
  return "dangerous";
}

export function clampScore(score: number): number {
  if (!Number.isFinite(score)) return 0;
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

export function maxConfidence(a: Confidence, b: Confidence): Confidence {
  return CONFIDENCE_ORDER[a] >= CONFIDENCE_ORDER[b] ? a : b;
}

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER[severity];
}

export function compareFindings(a: SecurityFinding, b: SecurityFinding): number {
  const penalty = b.penalty - a.penalty;
  if (penalty !== 0) return penalty;
  return SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
}

export function isCriticalFinding(finding: SecurityFinding): boolean {
  return finding.severity === "critical" && finding.confidence !== "low";
}

export function classificationLabel(classification: Classification): string {
  switch (classification) {
    case "safe":
      return "Safe";
    case "caution":
      return "Be Careful";
    case "dangerous":
      return "Dangerous";
    default:
      return "Unknown";
  }
}

export function severityLabel(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    default:
      return "Info";
  }
}
