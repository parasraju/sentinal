import type { PermissionState } from "../shared/types";

export async function getPermissionState(
  origin: string | null,
  contentScriptAvailable: boolean,
): Promise<PermissionState> {
  let cookies = false;
  let hostAccess = false;
  let dnrFeedback = false;

  try {
    cookies = await chrome.permissions.contains({ permissions: ["cookies"] });
  } catch {
    cookies = false;
  }

  if (origin) {
    try {
      hostAccess = await chrome.permissions.contains({ origins: [`${origin}/*`] });
    } catch {
      hostAccess = false;
    }
  }

  try {
    dnrFeedback = await chrome.permissions.contains({
      permissions: ["declarativeNetRequestFeedback"],
    });
  } catch {
    dnrFeedback = false;
  }

  const missing: string[] = [];
  if (!cookies) missing.push("cookie metadata access");
  if (!hostAccess) missing.push("site access");
  if (!contentScriptAvailable) missing.push("page inspection");

  return {
    cookies,
    hostAccess,
    contentScript: contentScriptAvailable,
    dnrFeedback,
    message:
      missing.length > 0
        ? `Unavailable: ${missing.join(", ")}. Missing evidence is reported as unknown, not safe.`
        : null,
  };
}
