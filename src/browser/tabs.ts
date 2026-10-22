import type { PageEvidence } from "../shared/types";
import { getActionApi, getExtensionApi } from "./extension-api";

export function isAssessableUrl(url: string | undefined): url is string {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

export async function getActiveTab(): Promise<chrome.tabs.Tab | null> {
  const api = getExtensionApi();
  if (!api?.tabs) return null;
  const tabs = await api.tabs.query({ active: true, currentWindow: true });
  return tabs[0] ?? null;
}

export async function getTab(tabId: number): Promise<chrome.tabs.Tab | null> {
  try {
    const api = getExtensionApi();
    return api?.tabs ? await api.tabs.get(tabId) : null;
  } catch {
    return null;
  }
}

export async function injectContentScript(tabId: number): Promise<boolean> {
  try {
    const api = getExtensionApi();
    if (!api?.scripting) return false;
    await api.scripting.executeScript({
      target: { tabId },
      files: ["content/content-script.js"],
    });
    return true;
  } catch {
    return false;
  }
}

export interface EvidenceRequestResult {
  evidence: PageEvidence | null;
  contentScript: boolean;
}

/** Asks the content script for a fresh snapshot, injecting it once if missing. */
export async function requestPageEvidence(
  tabId: number,
  timeoutMs = 1800,
): Promise<EvidenceRequestResult> {
  const ask = async (): Promise<PageEvidence | null> => {
    try {
      const api = getExtensionApi();
      if (!api?.tabs) return null;
      const response = (await api.tabs.sendMessage(tabId, { type: "REQUEST_EVIDENCE" })) as
        | { evidence?: PageEvidence }
        | undefined;
      return response?.evidence ?? null;
    } catch {
      return null;
    }
  };

  const withTimeout = async (promise: Promise<PageEvidence | null>): Promise<PageEvidence | null> =>
    Promise.race([
      promise,
      new Promise<null>((resolve) => {
        setTimeout(() => resolve(null), timeoutMs);
      }),
    ]);

  let evidence = await withTimeout(ask());
  if (evidence) return { evidence, contentScript: true };

  const injected = await injectContentScript(tabId);
  if (injected) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    evidence = await withTimeout(ask());
  }
  return { evidence, contentScript: Boolean(evidence) };
}

export async function setBadge(tabId: number, text: string, color: string, title: string): Promise<void> {
  try {
    const action = getActionApi();
    if (!action) return;
    await action.setBadgeBackgroundColor({ tabId, color });
    await action.setBadgeText({ tabId, text });
    await action.setTitle({ tabId, title });
  } catch {
    // Tab may have closed between assessment and badge update.
  }
}

export async function clearBadge(tabId: number): Promise<void> {
  try {
    const action = getActionApi();
    if (!action) return;
    await action.setBadgeText({ tabId, text: "" });
  } catch {
    // Ignore.
  }
}
