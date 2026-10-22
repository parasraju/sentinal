import { TRACKER_DB } from "./tracker-detector";
import { PENALTIES } from "../shared/constants";
import type {
  Confidence,
  CookieAnalysis,
  CookiePurpose,
  CookieReport,
  CookieSnapshot,
  SecurityFinding,
} from "../shared/types";

const SESSION_NAME =
  /(^|[-_.])(sess|session|sid|auth|token|jwt|login|remember|csrf|xsrf|secure|access|refresh)([-_.]|$)/i;
const TRACKING_NAME =
  /^(_ga|_gid|_gat|_gcl|_fbp|_fbc|_uet|_hj|_clck|_clsk|_uetsid|_uetvid|ajs_|mp_|amplitude_|optimizely|vwo_|hubspotutk|__hstc|__hssc|__hssrc|mUID|muid|visitor|track|ads?|ide|test_cookie|personalization_id)/i;
const FUNCTIONAL_NAME = /^(lang|locale|currency|theme|consent|cookieconsent|prefs?|settings|timezone|tz|country|region)$/i;
function daysUntil(expirationDate: number | null, now: number): number | null {
  if (!expirationDate) return null;
  return Math.max(0, Math.round((expirationDate - now / 1000) / 86400));
}

function matchesTrackerDomain(domain: string): boolean {
  const host = domain.replace(/^\./, "").toLowerCase();
  return TRACKER_DB.some((tracker) => host === tracker.domain || host.endsWith(`.${tracker.domain}`));
}

export function isSessionLikeName(name: string): boolean {
  return SESSION_NAME.test(name);
}

export function isTrackingLikeName(name: string): boolean {
  return TRACKING_NAME.test(name);
}

export function analyzeCookies(
  cookies: CookieSnapshot[] | null,
  pageUrl: string,
  now = Date.now(),
  options: { reason?: string | null; deletedThisSession?: number } = {},
): CookieReport {
  if (cookies === null) {
    return {
      available: false,
      reason: options.reason ?? "Cookie access is unavailable for this page.",
      total: 0,
      firstPartyCount: 0,
      thirdPartyCount: 0,
      sessionCount: 0,
      trackingCount: 0,
      concernCount: 0,
      cookies: [],
      findings: [],
      limitations: [
        "Cookie metadata could not be read. Missing cookie evidence is not evidence that no cookies exist.",
      ],
      deletedThisSession: options.deletedThisSession ?? 0,
    };
  }

  const analyses: CookieAnalysis[] = cookies.map((cookie) => {
    const purposes: CookiePurpose[] = [];
    const concerns: string[] = [];
    const notes: string[] = [];
    let confidence: Confidence = "low";
    const name = cookie.name;
    const days = daysUntil(cookie.expirationDate, now);
    const sessionLike = isSessionLikeName(name);
    const trackingLike = isTrackingLikeName(name) || matchesTrackerDomain(cookie.domain);
    const functional = FUNCTIONAL_NAME.test(name);

    if (trackingLike) {
      purposes.push("tracking");
      notes.push("Classified as tracking-related from its name and/or domain. Purpose is inferred, not proven.");
      confidence = "medium";
    }

    if (sessionLike) {
      purposes.push("session");
      confidence = "medium";
      notes.push("Name suggests a login or session role. This extension cannot confirm the cookie's actual purpose.");
    } else if (cookie.session) {
      purposes.push("session");
      notes.push("Session cookie: it expires when the browser session ends.");
      if (confidence === "low") confidence = "medium";
    }

    if (functional && purposes.length === 0) {
      purposes.push("functional");
      notes.push("Name matches a common preference or consent cookie pattern.");
      confidence = "medium";
    }

    if (sessionLike && !cookie.secure) {
      concerns.push("Missing Secure attribute: under applicable browser conditions the cookie may be sent over an unencrypted HTTP request.");
    }
    if (sessionLike && !cookie.httpOnly) {
      concerns.push("Missing HttpOnly attribute: JavaScript running on this site can read the cookie.");
    }
    if (cookie.sameSite === "no_restriction" && !cookie.secure) {
      concerns.push("SameSite=None without Secure: Chromium may reject this cookie, and cross-site sending is enabled where accepted.");
    }
    if (trackingLike && days !== null && days > 180) {
      concerns.push(`Long-lived tracking cookie: expires in about ${days} days, allowing persistent browser recognition.`);
    }
    if (cookie.firstParty === false && trackingLike && !cookie.secure) {
      concerns.push("Third-party tracking cookie without the Secure attribute.");
    }
    if (cookie.firstParty === false && purposes.length === 0) {
      notes.push("Third-party cookie. Not all third-party cookies are trackers; purpose here is unknown.");
    }

    if (concerns.length > 0) {
      purposes.unshift("security-concern");
      confidence = "high";
    }
    if (purposes.length === 0) {
      purposes.push("unknown");
      confidence = "low";
    }

    return {
      key: `${cookie.storeId}|${cookie.domain}|${cookie.path}|${name}`,
      name,
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite,
      session: cookie.session,
      expirationDate: cookie.expirationDate,
      firstParty: cookie.firstParty,
      purposes: Array.from(new Set(purposes)),
      confidence,
      concerns,
      notes,
      deletable: Boolean(name) && !cookie.hostOnly ? true : Boolean(name),
    };
  });

  const firstPartyCount = analyses.filter((cookie) => cookie.firstParty === true).length;
  const thirdPartyCount = analyses.filter((cookie) => cookie.firstParty === false).length;
  const sessionCount = analyses.filter((cookie) => cookie.purposes.includes("session")).length;
  const trackingCount = analyses.filter((cookie) => cookie.purposes.includes("tracking")).length;
  const concernCount = analyses.filter((cookie) => cookie.concerns.length > 0).length;

  const findings: SecurityFinding[] = [];
  const sessionConcerns = analyses.filter(
    (cookie) => cookie.purposes.includes("session") && cookie.concerns.length > 0,
  );
  if (sessionConcerns.length > 0) {
    findings.push({
      id: "cookie:session-security",
      category: "cookie",
      severity: "medium",
      confidence: "medium",
      title: "Session-like cookies lack security attributes",
      explanation: `${sessionConcerns.length} cookie${sessionConcerns.length === 1 ? "" : "s"} with names suggesting authentication or session state lack Secure and/or HttpOnly. Cookie names are heuristics; the actual role is not proven.`,
      evidence: sessionConcerns.slice(0, 6).map((cookie) => `${cookie.name} (${cookie.domain})`),
      remediation:
        "Treat this as a site-quality issue. Avoid typing credentials when other risk indicators are present. Site owners should set Secure and HttpOnly on session cookies.",
      source: "observed",
      penalty: PENALTIES.missingCookieSecurity,
    });
  }

  if (thirdPartyCount > 0) {
    const names = analyses.filter((cookie) => cookie.firstParty === false).slice(0, 5).map((cookie) => cookie.name);
    findings.push({
      id: "cookie:third-party",
      category: "cookie",
      severity: "low",
      confidence: "medium",
      title: "Third-party cookies are present",
      explanation: `${thirdPartyCount} cookie${thirdPartyCount === 1 ? "" : "s"} belong to a different registrable domain than ${new URL(pageUrl).hostname}. Third-party cookies are often used for tracking, though some support embedded features.`,
      evidence: names,
      remediation: "Review and remove tracking-related cookies, or enable tracker blocking.",
      source: "observed",
      penalty: PENALTIES.thirdPartyCookies,
    });
  }

  const longLivedTrackers = analyses.filter(
    (cookie) => cookie.purposes.includes("tracking") && cookie.concerns.some((concern) => concern.startsWith("Long-lived")),
  );
  if (longLivedTrackers.length > 0) {
    findings.push({
      id: "cookie:tracking-persistence",
      category: "cookie",
      severity: "info",
      confidence: "medium",
      title: "Persistent tracking cookies observed",
      explanation: `${longLivedTrackers.length} tracking-like cookie${longLivedTrackers.length === 1 ? "" : "s"} persist for more than 180 days. This can allow persistent recognition of the browser. No cookie values were read.`,
      evidence: longLivedTrackers.slice(0, 6).map((cookie) => `${cookie.name} (${cookie.domain})`),
      remediation: "Remove selected tracking cookies from the Cookie Manager if you do not need the associated features.",
      source: "observed",
      penalty: 0,
    });
  }

  return {
    available: true,
    reason: null,
    total: analyses.length,
    firstPartyCount,
    thirdPartyCount,
    sessionCount,
    trackingCount,
    concernCount,
    cookies: analyses,
    findings,
    limitations: [
      "Cookie purpose is inferred from name, attributes, and domain — not from observed behavior.",
      "A cookie marked as a concern is not proof of compromise or session theft.",
      "The Cookie API exposes cookies applicable to this URL and cookie store. Cookie values are never read or stored.",
      "First-party versus third-party context is inferred from the cookie domain; embedded third-party contexts cannot be fully determined.",
    ],
    deletedThisSession: options.deletedThisSession ?? 0,
  };
}
