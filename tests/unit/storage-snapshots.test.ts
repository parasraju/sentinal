import { afterEach, describe, expect, it, vi } from "vitest";
import { clearMemorySnapshots, readSnapshot, saveSnapshot } from "../../src/storage/snapshots";
import type { TabSnapshot } from "../../src/shared/types";

const snapshot = { tabId: 42, url: "https://example.test/" } as TabSnapshot;

function installChrome(session?: Partial<chrome.storage.StorageArea>): void {
  vi.stubGlobal("chrome", {
    storage: {
      local: {},
      ...(session === undefined ? {} : { session }),
    },
  });
}

afterEach(() => {
  clearMemorySnapshots();
  vi.unstubAllGlobals();
});

describe("snapshot session storage fallback", () => {
  it("keeps snapshots in memory when session storage is unavailable", async () => {
    installChrome();

    await saveSnapshot(snapshot);

    await expect(readSnapshot(snapshot.tabId)).resolves.toEqual(snapshot);
  });

  it("keeps snapshots in memory when session storage rejects", async () => {
    installChrome({
      set: vi.fn().mockRejectedValue(new Error("unsupported")),
      get: vi.fn().mockRejectedValue(new Error("unsupported")),
    });

    await saveSnapshot(snapshot);

    await expect(readSnapshot(snapshot.tabId)).resolves.toEqual(snapshot);
  });

  it("does not write fallback snapshots to local storage", async () => {
    const localSet = vi.fn();
    installChrome({ set: vi.fn().mockRejectedValue(new Error("unsupported")) });
    (globalThis.chrome.storage as unknown as { local: { set: typeof localSet } }).local = { set: localSet };

    await saveSnapshot(snapshot);

    expect(localSet).not.toHaveBeenCalled();
  });
});
