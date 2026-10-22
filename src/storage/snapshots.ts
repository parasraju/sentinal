import { SNAPSHOT_KEY_PREFIX } from "../shared/constants";
import type { TabSnapshot } from "../shared/types";

function keyFor(tabId: number): string {
  return `${SNAPSHOT_KEY_PREFIX}${tabId}`;
}

export async function saveSnapshot(snapshot: TabSnapshot): Promise<void> {
  try {
    await chrome.storage.session.set({ [keyFor(snapshot.tabId)]: snapshot });
  } catch {
    // Session storage can fail after a service-worker restart; assessment still works in-memory.
  }
}

export async function readSnapshot(tabId: number): Promise<TabSnapshot | null> {
  try {
    const stored = await chrome.storage.session.get(keyFor(tabId));
    const snapshot = stored[keyFor(tabId)];
    return snapshot && typeof snapshot === "object" ? (snapshot as TabSnapshot) : null;
  } catch {
    return null;
  }
}

export async function deleteSnapshot(tabId: number): Promise<void> {
  try {
    await chrome.storage.session.remove(keyFor(tabId));
  } catch {
    // Ignore cleanup failures.
  }
}
