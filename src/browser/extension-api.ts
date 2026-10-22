type ExtensionApi = typeof chrome & {
  browser?: typeof chrome;
};

type ActionApi = typeof chrome.action;

const extensionApi = globalThis as typeof globalThis & ExtensionApi;

/**
 * Firefox exposes the WebExtension API as `browser`, while Chromium exposes
 * `chrome`. Firefox also retains `browserAction` in some MV3 environments.
 * Prefer the standard MV3 action API and fall back without assuming either
 * namespace is present during unit tests or partial browser implementations.
 */
export function getExtensionApi(): typeof chrome | null {
  return extensionApi.chrome ?? extensionApi.browser ?? null;
}

export function getActionApi(): ActionApi | typeof chrome.browserAction | null {
  const api = getExtensionApi();
  if (!api) return null;
  return api.action ?? api.browserAction ?? null;
}

export function getSessionStorage(): chrome.storage.StorageArea | null {
  return getExtensionApi()?.storage?.session ?? null;
}
