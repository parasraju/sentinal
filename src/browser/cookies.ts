import type { CookieSnapshot, SameSiteValue } from "../shared/types";
import { registrableDomainOf, sanitizeCookie } from "../shared/validation";

export interface CookieReadResult {
  cookies: CookieSnapshot[] | null;
  reason: string | null;
}

function sameSiteOf(value: chrome.cookies.SameSiteStatus | undefined): SameSiteValue {
  if (value === "no_restriction" || value === "lax" || value === "strict") return value;
  return "unspecified";
}

export function firstPartyContext(cookieDomain: string, pageUrl: string): boolean | null {
  try {
    const page = registrableDomainOf(new URL(pageUrl).hostname);
    const cookie = registrableDomainOf(cookieDomain.replace(/^\./, ""));
    if (!page || !cookie) return null;
    return page === cookie;
  } catch {
    return null;
  }
}

export async function getCookiesForUrl(url: string): Promise<CookieReadResult> {
  try {
    const raw = await chrome.cookies.getAll({ url });
    const cookies: CookieSnapshot[] = [];
    for (const cookie of raw) {
      const firstParty = firstPartyContext(cookie.domain, url);
      const sanitized = sanitizeCookie({
        name: cookie.name,
        domain: cookie.domain,
        path: cookie.path,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite: sameSiteOf(cookie.sameSite),
        session: cookie.session,
        expirationDate: cookie.expirationDate ?? null,
        hostOnly: cookie.hostOnly,
        storeId: cookie.storeId,
        firstParty,
      });
      if (sanitized) cookies.push(sanitized);
    }
    return { cookies, reason: null };
  } catch (error) {
    const reason =
      error instanceof Error && error.message
        ? `Cookie access failed: ${error.message}`
        : "Cookie access is unavailable. The cookies permission or site access may be missing.";
    return { cookies: null, reason };
  }
}

export interface CookieDeleteInput {
  name: string;
  domain: string;
  path: string;
  storeId: string;
}

export interface CookieDeleteResult {
  deleted: number;
  failed: number;
  errors: string[];
}

function candidateUrls(input: CookieDeleteInput, tabUrl: string): string[] {
  const urls = new Set<string>();
  const host = input.domain.replace(/^\./, "");
  const path = input.path.startsWith("/") ? input.path : `/${input.path}`;
  const schemes = new Set(["https", "http"]);
  try {
    schemes.add(new URL(tabUrl).protocol.replace(":", ""));
  } catch {
    // Ignore malformed tab URL.
  }
  for (const scheme of schemes) {
    if (scheme === "http" || scheme === "https") urls.add(`${scheme}://${host}${path}`);
  }
  urls.add(tabUrl);
  return Array.from(urls);
}

export async function deleteCookie(
  input: CookieDeleteInput,
  tabUrl: string,
): Promise<{ ok: boolean; error: string | null }> {
  let lastError: string | null = null;
  for (const url of candidateUrls(input, tabUrl)) {
    try {
      const result = await chrome.cookies.remove({ url, name: input.name, storeId: input.storeId });
      if (result) return { ok: true, error: null };
      lastError = "The browser did not remove the cookie.";
    } catch (error) {
      lastError = error instanceof Error ? error.message : "Cookie removal failed.";
    }
  }
  return { ok: false, error: lastError };
}

export async function deleteCookies(
  inputs: CookieDeleteInput[],
  tabUrl: string,
): Promise<CookieDeleteResult> {
  let deleted = 0;
  let failed = 0;
  const errors: string[] = [];
  const capped = inputs.slice(0, 200);
  for (const input of capped) {
    const result = await deleteCookie(input, tabUrl);
    if (result.ok) deleted += 1;
    else {
      failed += 1;
      if (result.error && errors.length < 5) errors.push(`${input.name}: ${result.error}`);
    }
  }
  return { deleted, failed, errors };
}
