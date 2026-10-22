import { SNAPSHOT_KEY_PREFIX } from "../shared/constants";
import type { TabSnapshot } from "../shared/types";
import { getSessionStorage } from "../browser/extension-api";

function keyFor(tabId: number): string {
  return `${SNAPSHOT_KEY_PREFIX}${tabId}`;
}

const memorySnapshots = new Map<string, TabSnapshot>();

function sessionStorage(): chrome.storage.StorageArea | null {
  return getSessionStorage();
}

export async function saveSnapshot(snapshot: TabSnapshot): Promise<void> {
  const key = keyFor(snapshot.tabId);
  try {
    const session = sessionStorage();
    if (!session) throw new Error("Session storage is unavailable.");
    await session.set({ [key]: snapshot });
    memorySnapshots.delete(key);
  } catch {
    // Never fall back to persistent storage: snapshots can contain sensitive page data.
    memorySnapshots.set(key, snapshot);
  }
}

export async function readSnapshot(tabId: number): Promise<TabSnapshot | null> {
  const key = keyFor(tabId);
  try {
    const session = sessionStorage();
    if (!session) throw new Error("Session storage is unavailable.");
    const stored = await session.get(key);
    const snapshot = stored[key];
    return snapshot && typeof snapshot === "object" ? (snapshot as TabSnapshot) : null;
  } catch {
    return memorySnapshots.get(key) ?? null;
  }
}

export async function deleteSnapshot(tabId: number): Promise<void> {
  const key = keyFor(tabId);
  memorySnapshots.delete(key);
  try {
    const session = sessionStorage();
    if (!session) return;
    await session.remove(key);
  } catch {
    // Ignore cleanup failures.
  }
}

export function clearMemorySnapshots(): void {
  memorySnapshots.clear();
}
