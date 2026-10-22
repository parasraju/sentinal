import {
  ALL_RULESET_IDS,
  DNR_LAST_SYNC_KEY,
  DNR_RULE_ID_BASE,
  STRICT_RULESET_ID,
} from "../shared/constants";
import type { ProtectionStatus, Settings, TrackerCategory } from "../shared/types";
import { normalizeAllowlistDomain } from "../shared/validation";

const BLOCKED_RESOURCE_TYPES = [
  "script",
  "image",
  "xmlhttprequest",
  "sub_frame",
  "stylesheet",
  "font",
  "media",
  "websocket",
  "ping",
] as unknown as chrome.declarativeNetRequest.ResourceType[];

const RULESET_IDS = new Set<string>(ALL_RULESET_IDS);

export function computeEnabledRulesets(settings: Settings): string[] {
  if (settings.protectionMode === "off") return [];
  if (settings.protectionMode === "strict") {
    return ["analytics", "advertising", "social", "session_replay", "fingerprinting", STRICT_RULESET_ID];
  }
  const categoryMap: Record<TrackerCategory, string> = {
    analytics: "analytics",
    advertising: "advertising",
    social: "social",
    session_replay: "session_replay",
    fingerprinting: "fingerprinting",
  };
  const enabled: string[] = [];
  for (const category of Object.keys(categoryMap) as TrackerCategory[]) {
    if (settings.blockCategories[category]) enabled.push(categoryMap[category]);
  }
  if (settings.strictExtra) enabled.push(STRICT_RULESET_ID);
  return enabled;
}

export function validateAllowlistRules(domains: string[]): {
  valid: string[];
  rejected: string[];
} {
  const valid: string[] = [];
  const rejected: string[] = [];
  for (const domain of domains.slice(0, 200)) {
    const normalized = normalizeAllowlistDomain(domain);
    if (normalized) valid.push(normalized);
    else rejected.push(domain);
  }
  return { valid, rejected };
}

export function buildAllowlistRules(domains: string[]): chrome.declarativeNetRequest.Rule[] {
  const { valid } = validateAllowlistRules(domains);
  return valid.map((domain, index) => ({
    id: DNR_RULE_ID_BASE + index,
    priority: 100,
    action: { type: "allow" as chrome.declarativeNetRequest.RuleActionType },
    condition: {
      initiatorDomains: [domain],
      resourceTypes: BLOCKED_RESOURCE_TYPES,
    },
  }));
}

export function isValidTrackerRuleset(id: string): boolean {
  return RULESET_IDS.has(id);
}

async function setEnabledRulesets(enabled: string[]): Promise<void> {
  const desired = new Set(enabled.filter(isValidTrackerRuleset));
  const disableRulesetIds = Array.from(RULESET_IDS).filter((id) => !desired.has(id));
  const enableRulesetIds = Array.from(desired);
  try {
    await chrome.declarativeNetRequest.updateEnabledRulesets({
      disableRulesetIds,
      enableRulesetIds,
    });
  } catch (error) {
    throw new Error(
      error instanceof Error
        ? `Could not update blocking rulesets: ${error.message}`
        : "Could not update blocking rulesets.",
    );
  }
}

async function syncAllowlistRules(domains: string[]): Promise<void> {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((rule) => rule.id >= DNR_RULE_ID_BASE && rule.id < DNR_RULE_ID_BASE + 1000)
    .map((rule) => rule.id);
  const addRules = buildAllowlistRules(domains);
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
}

export async function syncNetworkRules(settings: Settings): Promise<ProtectionStatus> {
  const enabledRulesets = computeEnabledRulesets(settings);
  try {
    await syncAllowlistRules(settings.allowlist);
    await setEnabledRulesets(enabledRulesets);
    await chrome.storage.local.set({ [DNR_LAST_SYNC_KEY]: Date.now() });
    return {
      enabledRulesets,
      dynamicAllowRules: buildAllowlistRules(settings.allowlist).length,
      mode: settings.protectionMode,
      blockingActive: enabledRulesets.length > 0,
      allowlisted: false,
      lastSyncedAt: Date.now(),
      error: null,
    };
  } catch (error) {
    return {
      enabledRulesets: [],
      dynamicAllowRules: 0,
      mode: settings.protectionMode,
      blockingActive: false,
      allowlisted: false,
      lastSyncedAt: null,
      error: error instanceof Error ? error.message : "Network rule synchronization failed.",
    };
  }
}

export async function getProtectionStatus(
  settings: Settings,
  allowlisted: boolean,
): Promise<ProtectionStatus> {
  let enabledRulesets: string[] = [];
  let dynamicRules = 0;
  let lastSyncedAt: number | null = null;
  let error: string | null = null;
  try {
    enabledRulesets = (await chrome.declarativeNetRequest.getEnabledRulesets()).filter(isValidTrackerRuleset);
  } catch (cause) {
    error = cause instanceof Error ? cause.message : "Could not read enabled rulesets.";
  }
  try {
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    dynamicRules = rules.filter((rule) => rule.id >= DNR_RULE_ID_BASE && rule.id < DNR_RULE_ID_BASE + 1000).length;
  } catch {
    dynamicRules = 0;
  }
  try {
    const stored = await chrome.storage.local.get(DNR_LAST_SYNC_KEY);
    lastSyncedAt = typeof stored[DNR_LAST_SYNC_KEY] === "number" ? stored[DNR_LAST_SYNC_KEY] : null;
  } catch {
    lastSyncedAt = null;
  }

  return {
    enabledRulesets,
    dynamicAllowRules: dynamicRules,
    mode: settings.protectionMode,
    blockingActive: enabledRulesets.length > 0 && !allowlisted,
    allowlisted,
    lastSyncedAt,
    error,
  };
}

export async function getBlockedRecentCount(tabId: number): Promise<number | null> {
  try {
    const result = await chrome.declarativeNetRequest.getMatchedRules({ tabId });
    const info = result.rulesMatchedInfo ?? [];
    return info.filter((entry) => isValidTrackerRuleset(entry.rule.rulesetId ?? "")).length;
  } catch {
    return null;
  }
}

export async function restoreDefaultRulesets(settings: Settings): Promise<ProtectionStatus> {
  return syncNetworkRules(settings);
}
