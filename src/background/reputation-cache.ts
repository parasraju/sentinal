import { REPUTATION_CACHE_KEY } from "../shared/constants";
import type { ReputationCacheAdapter } from "../security/reputation";
import type { ReputationResult } from "../shared/types";

interface CacheEntry {
  result: ReputationResult;
  expiresAt: number;
}

interface CacheShape {
  version: number;
  entries: Record<string, CacheEntry>;
}

const MAX_ENTRIES = 200;

async function readCache(): Promise<CacheShape> {
  const stored = await chrome.storage.local.get(REPUTATION_CACHE_KEY);
  const raw = stored[REPUTATION_CACHE_KEY];
  if (!raw || typeof raw !== "object") return { version: 1, entries: {} };
  const candidate = raw as Partial<CacheShape>;
  const entries = candidate.entries && typeof candidate.entries === "object" ? candidate.entries : {};
  return { version: 1, entries };
}

async function writeCache(cache: CacheShape): Promise<void> {
  const now = Date.now();
  const entries = Object.entries(cache.entries)
    .filter(([, entry]) => entry && entry.expiresAt > now)
    .slice(-MAX_ENTRIES);
  await chrome.storage.local.set({
    [REPUTATION_CACHE_KEY]: { version: 1, entries: Object.fromEntries(entries) },
  });
}

export const reputationCache: ReputationCacheAdapter = {
  async get(domain) {
    const cache = await readCache();
    const entry = cache.entries[domain];
    if (!entry || typeof entry.expiresAt !== "number") return null;
    return entry;
  },
  async set(domain, result, expiresAt) {
    const cache = await readCache();
    cache.entries[domain] = { result, expiresAt };
    await writeCache(cache);
  },
};
