import knownBad from "../data/known-bad-domains.json";
import type { ReputationMatch, ReputationResult } from "../shared/types";

export interface LocalReputationEntry {
  domain: string;
  label: string;
  severity: "critical" | "high";
  source: string;
}

const ENTRIES: LocalReputationEntry[] = knownBad.entries
  .filter(
    (entry) =>
      typeof entry.domain === "string" &&
      typeof entry.label === "string" &&
      (entry.severity === "critical" || entry.severity === "high"),
  )
  .map((entry): LocalReputationEntry => ({
    domain: entry.domain.toLowerCase(),
    label: entry.label,
    severity: entry.severity as LocalReputationEntry["severity"],
    source: entry.source || "local-list",
  }));

export const LOCAL_REPUTATION_LIST_VERSION = knownBad.version;

export function findLocalReputation(hostname: string | null, now = Date.now()): ReputationMatch | null {
  if (!hostname) return null;
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const entry = ENTRIES.find(
    (candidate) => host === candidate.domain || host.endsWith(`.${candidate.domain}`),
  );
  if (!entry) return null;
  return {
    domain: entry.domain,
    label: entry.label,
    severity: entry.severity,
    source: entry.source,
    providerId: "sentinel-local",
    fetchedAt: now,
  };
}

export function findBadHosts(hosts: string[], now = Date.now()): ReputationMatch[] {
  const matches = new Map<string, ReputationMatch>();
  for (const host of hosts) {
    const match = findLocalReputation(host, now);
    if (match) matches.set(match.domain, match);
  }
  return Array.from(matches.values());
}

export interface ReputationProvider {
  id: string;
  /** Receives a registrable domain only — never a full URL or page content. */
  lookup(domain: string): Promise<ReputationResult>;
}

export class LocalReputationProvider implements ReputationProvider {
  id = "sentinel-local";

  async lookup(domain: string): Promise<ReputationResult> {
    const match = findLocalReputation(domain);
    return {
      matches: match ? [match] : [],
      providerId: this.id,
      available: true,
      reason: null,
      cached: false,
    };
  }
}

export class UrlScanReputationProvider implements ReputationProvider {
  id = "urlscan-threat-intel";

  constructor(
    private readonly timeoutMs = 4000,
    private readonly fetchFn: typeof fetch = globalThis.fetch,
  ) {}

  async lookup(domain: string): Promise<ReputationResult> {
    if (!domain || !this.fetchFn) {
      return { matches: [], providerId: this.id, available: false, reason: "No domain or network fetch available.", cached: false };
    }
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const url = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=5`;
      const res = await this.fetchFn(url, {
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (!res.ok) {
        return { matches: [], providerId: this.id, available: false, reason: `URLScan returned HTTP ${res.status}`, cached: false };
      }
      const data = (await res.json()) as {
        results?: Array<{
          task?: { time?: string };
          verdicts?: { overall?: { malicious?: boolean; score?: number; categories?: string[] } };
        }>;
      };
      const matches: ReputationMatch[] = [];
      if (Array.isArray(data.results)) {
        const maliciousScans = data.results.filter((r) => r.verdicts?.overall?.malicious === true);
        if (maliciousScans.length > 0) {
          matches.push({
            domain,
            label: "Flagged malicious on URLScan.io community intelligence feed",
            severity: "critical",
            source: "threat-intel",
            providerId: this.id,
            fetchedAt: Date.now(),
          });
        }
      }
      return {
        matches,
        providerId: this.id,
        available: true,
        reason: null,
        cached: false,
      };
    } catch (err) {
      clearTimeout(timeoutId);
      return {
        matches: [],
        providerId: this.id,
        available: false,
        reason: err instanceof Error ? err.message : "URLScan lookup failed",
        cached: false,
      };
    }
  }
}

export interface ReputationCacheAdapter {
  get(domain: string): Promise<{ result: ReputationResult; expiresAt: number } | null>;
  set(domain: string, result: ReputationResult, expiresAt: number): Promise<void>;
}

export class ReputationService {
  constructor(
    private readonly providers: ReputationProvider[],
    private readonly cache: ReputationCacheAdapter | null = null,
    private readonly ttlMs = 24 * 60 * 60 * 1000,
    private readonly now: () => number = () => Date.now(),
  ) {}

  async lookup(domain: string | null): Promise<ReputationResult> {
    if (!domain) {
      return {
        matches: [],
        providerId: "none",
        available: false,
        reason: "No registrable domain was available for reputation lookup.",
        cached: false,
      };
    }

    if (this.cache) {
      try {
        const cached = await this.cache.get(domain);
        if (cached && cached.expiresAt > this.now()) {
          return { ...cached.result, cached: true };
        }
      } catch {
        // Cache failures must never block assessment.
      }
    }

    for (const provider of this.providers) {
      try {
        const result = await provider.lookup(domain);
        if (result.available && result.matches.length > 0) {
          if (this.cache) {
            try {
              await this.cache.set(
                domain,
                { ...result, cached: false },
                this.now() + this.ttlMs,
              );
            } catch {
              // Ignore cache write failures.
            }
          }
          return result;
        }
      } catch {
        // Try the next provider; an unavailable feed is not a safe signal.
      }
    }

    return {
      matches: [],
      providerId: this.providers[0]?.id ?? "none",
      available: this.providers.length > 0,
      reason:
        this.providers.length === 0
          ? "No reputation provider is configured."
          : "No reputation match was found in the available local providers.",
      cached: false,
    };
  }
}
