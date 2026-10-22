import { assessTab, cacheEvidence, clearTabCache } from "./pipeline";
import { getActiveTab, getTab, isAssessableUrl } from "../browser/tabs";
import { deleteCookie, deleteCookies } from "../browser/cookies";
import { syncNetworkRules } from "../browser/network-rules";
import { clearHistory, getHistory } from "../storage/history";
import { clearAllLocalData, getSettings, saveSettings, setAllowlistDomain, incrementDeletedCookieCount } from "../storage/settings";
import type { ExtensionMessage } from "../shared/messages";
import type { SubmissionRiskInput } from "../shared/types";

async function broadcast(tabId: number, snapshot: Awaited<ReturnType<typeof assessTab>>): Promise<void> {
  const message = { type: "SNAPSHOT_UPDATED", tabId, assessment: snapshot.assessment, allowlisted: snapshot.allowlisted } as const;
  try { await chrome.runtime.sendMessage(message); } catch { /* no extension page is open */ }
  try { await chrome.tabs.sendMessage(tabId, message); } catch { /* content script may be unavailable */ }
}

async function assessAndBroadcast(tabId: number, force = false) {
  const snapshot = await assessTab(tabId, { force });
  await broadcast(tabId, snapshot);
  return snapshot;
}

async function submissionDecision(input: SubmissionRiskInput, senderTabId?: number) {
  const tab = senderTabId !== undefined ? await getTab(senderTabId) : await getActiveTab();
  if (!tab?.id || !tab.url || !isAssessableUrl(input.pageUrl) || tab.url !== input.pageUrl) return { decision: "allow" as const, title: "No warning", summary: "Sentinel could not assess this submission.", reasons: [], risk: "none" as const, assessment: null, allowlisted: false };
  const snapshot = await assessAndBroadcast(tab.id, false);
  const form = snapshot.forms.find((candidate) => candidate.formIndex === input.formIndex);
  const highRisk = form?.risk === "high" || form?.risk === "critical" || snapshot.assessment.critical || (input.hasPassword && snapshot.assessment.classification === "dangerous");
  return {
    decision: highRisk ? "warn" as const : "allow" as const,
    title: highRisk ? "Potential credential theft detected" : "Submission reviewed",
    summary: highRisk ? "Sentinel observed evidence that makes this submission unsafe to continue without verification." : "No high-confidence submission warning was found.",
    reasons: highRisk ? [...(form?.reasons ?? []), ...snapshot.assessment.topFactors].slice(0, 6) : [],
    risk: form?.risk ?? (snapshot.assessment.critical ? "critical" : "none"),
    assessment: snapshot.assessment,
    allowlisted: snapshot.allowlisted,
  };
}

chrome.runtime.onInstalled.addListener(() => { void getSettings().then(syncNetworkRules); });
chrome.runtime.onStartup.addListener(() => { void getSettings().then(syncNetworkRules); });
chrome.tabs.onRemoved.addListener((tabId) => clearTabCache(tabId));
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) void assessAndBroadcast(details.tabId, true).catch(() => undefined);
});

chrome.runtime.onMessage.addListener((message: ExtensionMessage, sender, sendResponse) => {
  void (async () => {
    try {
      switch (message.type) {
        case "CONTENT_READY": {
          const tabId = sender.tab?.id;
          sendResponse({ ok: true, publicSettings: tabId ? { sensitiveFormWarnings: (await getSettings()).sensitiveFormWarnings, suspiciousScriptAlerts: (await getSettings()).suspiciousScriptAlerts, suspiciousScriptAlertsLabel: "Static indicators only", allowlisted: false } : null });
          return;
        }
        case "PAGE_EVIDENCE": {
          const tabId = sender.tab?.id;
          if (tabId !== undefined) cacheEvidence(tabId, message.evidence);
          sendResponse({ ok: true });
          if (tabId !== undefined) void assessAndBroadcast(tabId, true).catch(() => undefined);
          return;
        }
        case "GET_SNAPSHOT": {
          const tab = message.tabId !== undefined ? await getTab(message.tabId) : await getActiveTab();
          if (!tab?.id) { sendResponse({ ok: false, snapshot: null, error: "No active tab is available." }); return; }
          const snapshot = await assessAndBroadcast(tab.id, message.force === true);
          sendResponse({ ok: true, snapshot, error: null });
          return;
        }
        case "RESCAN": {
          const tabId = message.tabId ?? (await getActiveTab())?.id;
          if (tabId === undefined) { sendResponse({ ok: false, snapshot: null, error: "No active tab is available." }); return; }
          sendResponse({ ok: true, snapshot: await assessAndBroadcast(tabId, true), error: null });
          return;
        }
        case "CHECK_SUBMISSION": sendResponse({ ok: true, decision: await submissionDecision(message.input, sender.tab?.id), error: null }); return;
        case "GET_SETTINGS": sendResponse({ ok: true, settings: await getSettings(), error: null }); return;
        case "UPDATE_SETTINGS": { const settings = await saveSettings(message.settings); await syncNetworkRules(settings); sendResponse({ ok: true, settings, error: null }); return; }
        case "GET_PROTECTION_STATUS": { const settings = await getSettings(); sendResponse({ ok: true, status: await syncNetworkRules(settings) }); return; }
        case "DELETE_COOKIE": {
          const tab = await getTab(message.tabId); const result = tab?.url ? await deleteCookie(message.cookie, tab.url) : { ok: false, error: "The tab URL is unavailable." };
          if (result.ok) await incrementDeletedCookieCount(1);
          const deletedThisSession = await incrementDeletedCookieCount(0);
          sendResponse({ ok: result.ok, deleted: result.ok ? 1 : 0, failed: result.ok ? 0 : 1, deletedThisSession, error: result.error }); return;
        }
        case "DELETE_COOKIES": {
          const tab = await getTab(message.tabId); const result = tab?.url ? await deleteCookies(message.cookies, tab.url) : { deleted: 0, failed: message.cookies.length, errors: ["The tab URL is unavailable."] };
          await incrementDeletedCookieCount(result.deleted); sendResponse({ ok: result.failed === 0, ...result, deletedThisSession: await incrementDeletedCookieCount(0) }); return;
        }
        case "GET_HISTORY": sendResponse({ ok: true, history: await getHistory(), error: null }); return;
        case "CLEAR_HISTORY": await clearHistory(); sendResponse({ ok: true, error: null }); return;
        case "CLEAR_ALL_DATA": await clearAllLocalData(); sendResponse({ ok: true, error: null }); return;
        case "SET_ALLOWLIST": { const settings = await setAllowlistDomain(message.domain, message.allowlisted); await syncNetworkRules(settings); sendResponse({ ok: true, error: null }); return; }
        case "OPEN_OPTIONS": await chrome.runtime.openOptionsPage(); sendResponse({ ok: true, error: null }); return;
      }
    } catch (error) { sendResponse({ ok: false, error: error instanceof Error ? error.message : "Sentinel operation failed." }); }
  })();
  return true;
});
