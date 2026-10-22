import {
  DEFAULT_SETTINGS,
  DELETED_COOKIE_COUNT_KEY,
  HISTORY_KEY,
  REPUTATION_CACHE_KEY,
  SETTINGS_KEY,
  SNAPSHOT_KEY_PREFIX,
} from "../shared/constants";
import type { Settings } from "../shared/types";
import { normalizeAllowlistDomain, normalizeSettings, sanitizeHostname } from "../shared/validation";

export async function getSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  const raw = stored[SETTINGS_KEY];
  if (raw === undefined) {
    const defaults = normalizeSettings(DEFAULT_SETTINGS);
    await chrome.storage.local.set({ [SETTINGS_KEY]: defaults });
    return defaults;
  }
  const normalized = normalizeSettings(raw);
  if (JSON.stringify(raw) !== JSON.stringify(normalized)) {
    await chrome.storage.local.set({ [SETTINGS_KEY]: normalized });
  }
  return normalized;
}

export async function saveSettings(next: Settings): Promise<Settings> {
  const normalized = normalizeSettings(next);
  await chrome.storage.local.set({ [SETTINGS_KEY]: normalized });
  return normalized;
}

export function isAllowlisted(settings: Settings, hostname: string | null): boolean {
  if (!hostname) return false;
  const host = sanitizeHostname(hostname);
  if (!host) return false;
  return settings.allowlist.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

export async function setAllowlistDomain(domain: string, allowlisted: boolean): Promise<Settings> {
  const normalizedDomain = normalizeAllowlistDomain(domain);
  if (!normalizedDomain) throw new Error("Invalid domain for the allowlist.");
  const settings = await getSettings();
  const allowlist = new Set(settings.allowlist);
  if (allowlisted) allowlist.add(normalizedDomain);
  else allowlist.delete(normalizedDomain);
  return saveSettings({ ...settings, allowlist: Array.from(allowlist) });
}

export async function getDeletedCookieCount(): Promise<number> {
  const stored = await chrome.storage.local.get(DELETED_COOKIE_COUNT_KEY);
  const value = stored[DELETED_COOKIE_COUNT_KEY];
  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
}

export async function incrementDeletedCookieCount(count: number): Promise<number> {
  const current = await getDeletedCookieCount();
  const next = current + Math.max(0, Math.floor(count));
  await chrome.storage.local.set({ [DELETED_COOKIE_COUNT_KEY]: next });
  return next;
}

export async function clearHistoryAndReputation(): Promise<void> {
  await chrome.storage.local.remove([HISTORY_KEY, REPUTATION_CACHE_KEY]);
}

export async function clearAllLocalData(): Promise<void> {
  const all = await chrome.storage.local.get(null);
  const snapshotKeys = Object.keys(all).filter((key) => key.startsWith(SNAPSHOT_KEY_PREFIX));
  const session = chrome.storage.session;
  if (session) {
    const sessionAll = await session.get(null);
    const sessionKeys = Object.keys(sessionAll);
    if (sessionKeys.length > 0) await session.remove(sessionKeys);
  }
  await chrome.storage.local.remove([SETTINGS_KEY, HISTORY_KEY, REPUTATION_CACHE_KEY, DELETED_COOKIE_COUNT_KEY]);
  if (snapshotKeys.length > 0) await chrome.storage.local.remove(snapshotKeys);
}
