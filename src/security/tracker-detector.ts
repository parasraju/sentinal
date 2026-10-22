import { parse } from "tldts";
import trackerData from "../data/trackers.json";
import { PENALTIES } from "../shared/constants";
import type {
  Confidence,
  ObservedResource,
  SecurityFinding,
  TrackerCategory,
  TrackerDefinition,
  TrackerObservation,
  TrackerReport,
} from "../shared/types";

const CATEGORIES = new Set<TrackerCategory>([
  "analytics",
  "advertising",
  "social",
  "session_replay",
  "fingerprinting",
]);

export const TRACKER_DB: TrackerDefinition[] = (trackerData as Array<Record<string, string>>)
  .filter(
    (entry) =>
      typeof entry.domain === "string" &&
      typeof entry.company === "string" &&
      typeof entry.category === "string" &&
      CATEGORIES.has(entry.category as TrackerCategory) &&
      (entry.confidence === "low" || entry.confidence === "medium" || entry.confidence === "high"),
  )
  .map((entry) => ({
    domain: (entry.domain as string).toLowerCase(),
    company: entry.company as string,
    category: entry.category as TrackerCategory,
    confidence: entry.confidence as Confidence,
    source: (entry.source as string) || "Sentinel tracker list",
  }));

const TRACKER_BY_LONGEST_DOMAIN = [...TRACKER_DB].sort((a, b) => b.domain.length - a.domain.length);

/** Exact or dot-boundary suffix matching only. `notgoogle-analytics.com` never matches. */
export function matchTrackerDomain(hostname: string): TrackerDefinition | null {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (!host) return null;
  return (
    TRACKER_BY_LONGEST_DOMAIN.find(
      (tracker) => host === tracker.domain || host.endsWith(`.${tracker.domain}`),
    ) ?? null
  );
}

function registrable(host: string): string {
  const parsed = parse(host, { allowPrivateDomains: true, detectIp: true });
  return parsed.domain ?? host;
}

function isThirdParty(resourceHost: string, pageHost: string): boolean {
  return registrable(resourceHost) !== registrable(pageHost);
}

export function analyzeTrackers(
  resources: ObservedResource[] | null,
  pageUrl: string,
  options: { blockedRecent?: number | null; now?: number } = {},
): TrackerReport {
  const limitations = [
    "Third-party requests are observed from the page's Resource Timing API and DOM metadata, which do not expose every request or response body.",
    "A third-party destination is not automatically a tracker; unknown services are listed separately.",
    "Request counts may be capped or unavailable for cross-origin or cached resources.",
    "Blocked counts, when shown, come from browser-reported rule matches and may cover only a recent window.",
  ];

  if (resources === null) {
    return {
      available: false,
      reason: "Page request evidence is unavailable (content script not running or permission denied).",
      observedThirdPartyDomains: 0,
      recognizedCount: 0,
      unknownCount: 0,
      thirdPartyRequestCount: 0,
      trackers: [],
      unknownDomains: [],
      blockedRecent: options.blockedRecent ?? null,
      blockedNote: "Blocking activity cannot be attributed without page evidence.",
      findings: [],
      limitations,
    };
  }

  let pageHost: string;
  try {
    pageHost = new URL(pageUrl).hostname;
  } catch {
    pageHost = "";
  }

  const thirdPartyResources = resources.filter(
    (resource) => !resource.firstParty && pageHost && isThirdParty(resource.host, pageHost),
  );

  const groups = new Map<
    string,
    { requests: number; types: Set<string>; recognized: TrackerDefinition | null }
  >();

  for (const resource of thirdPartyResources) {
    const existing = groups.get(resource.host);
    if (existing) {
      existing.requests += resource.count;
      existing.types.add(resource.type);
    } else {
      groups.set(resource.host, {
        requests: resource.count,
        types: new Set([resource.type]),
        recognized: matchTrackerDomain(resource.host),
      });
    }
  }

  const trackers: TrackerObservation[] = [];
  let thirdPartyRequestCount = 0;
  for (const [domain, group] of groups) {
    thirdPartyRequestCount += group.requests;
    const definition = group.recognized;
    trackers.push({
      domain,
      company: definition?.company ?? null,
      category: definition?.category ?? "unknown",
      confidence: definition?.confidence ?? null,
      source: definition?.source ?? null,
      requests: group.requests,
      resourceTypes: Array.from(group.types).sort(),
      recognized: Boolean(definition),
      blocked: null,
    });
  }

  trackers.sort((a, b) => {
    if (a.recognized !== b.recognized) return a.recognized ? -1 : 1;
    return b.requests - a.requests;
  });

  const recognized = trackers.filter((tracker) => tracker.recognized);
  const unknown = trackers.filter((tracker) => !tracker.recognized);

  const findings: SecurityFinding[] = [];
  if (recognized.length >= 3 || thirdPartyRequestCount >= 20) {
    findings.push({
      id: "tracker:significant-activity",
      category: "tracker",
      severity: "medium",
      confidence: "high",
      title: "Significant third-party tracking activity",
      explanation: `Observed ${recognized.length} recognized tracking domain${recognized.length === 1 ? "" : "s"} across ${thirdPartyRequestCount} third-party request${thirdPartyRequestCount === 1 ? "" : "s"}. Recognition comes from Sentinel's local tracker list, matched on exact domains or subdomains. This affects privacy, not necessarily the safety of the site.`,
      evidence: recognized
        .slice(0, 6)
        .map((tracker) => `${tracker.company} — ${tracker.domain} (${tracker.requests} request${tracker.requests === 1 ? "" : "s"})`),
      remediation:
        "Enable standard tracker blocking and review tracking cookies. Blocking may affect embedded content or site features.",
      source: "local-list",
      penalty: PENALTIES.significantTracking,
    });
  }

  if (unknown.length > 0 && recognized.length > 0) {
    findings.push({
      id: "tracker:unknown-third-parties",
      category: "tracker",
      severity: "info",
      confidence: "low",
      title: "Unknown third-party destinations observed",
      explanation: `${unknown.length} third-party domain${unknown.length === 1 ? "" : "s"} are not in Sentinel's local tracker list. They may be CDNs, payment services, or other functional providers — this is not evidence of tracking.`,
      evidence: unknown.slice(0, 6).map((tracker) => `${tracker.domain} (${tracker.requests} request${tracker.requests === 1 ? "" : "s"})`),
      remediation: "No action required unless the domain is unfamiliar and the page is asking for sensitive information.",
      source: "observed",
      penalty: 0,
    });
  }

  return {
    available: true,
    reason: null,
    observedThirdPartyDomains: trackers.length,
    recognizedCount: recognized.length,
    unknownCount: unknown.length,
    thirdPartyRequestCount,
    trackers,
    unknownDomains: unknown.map((tracker) => ({
      domain: tracker.domain,
      requests: tracker.requests,
      resourceTypes: tracker.resourceTypes,
    })),
    blockedRecent: options.blockedRecent ?? null,
    blockedNote:
      options.blockedRecent === null
        ? "Blocked-request counts are unavailable without the declarativeNetRequestFeedback permission."
        : "Counts only include rule matches retained by Chromium for this tab; they may not cover the full page load.",
    findings,
    limitations,
  };
}

export function trackerCategoryOf(hostname: string): TrackerCategory | null {
  return matchTrackerDomain(hostname)?.category ?? null;
}
