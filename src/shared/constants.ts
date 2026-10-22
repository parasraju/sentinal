import type { BlockCategories, ProtectionMode, Settings, TrackerCategory } from "./types";

export const EXTENSION_NAME = "Sentinel";
export const ASSESSMENT_VERSION = "1.0.0";
export const SETTINGS_VERSION = 1;
export const SETTINGS_KEY = "sentinel:settings:v1";
export const HISTORY_KEY = "sentinel:history:v1";
export const SNAPSHOT_KEY_PREFIX = "sentinel:snapshot:";
export const REPUTATION_CACHE_KEY = "sentinel:reputation:v1";
export const DELETED_COOKIE_COUNT_KEY = "sentinel:deleted-cookies:v1";
export const TRACKER_DB_VERSION = "2026-01";

export const SCORE_SAFE_MIN = 80;
export const SCORE_CAUTION_MIN = 40;

export const HISTORY_LIMIT = 100;
export const COOKIE_LIMIT = 400;
export const EVIDENCE_FORM_LIMIT = 30;
export const EVIDENCE_SCRIPT_LIMIT = 250;
export const EVIDENCE_RESOURCE_LIMIT = 400;
export const FINDING_LIMIT = 60;
export const TEXT_LIMIT = 400;

export const PENALTIES = {
  confirmedPhishing: 70,
  knownMalicious: 60,
  threatIntelMalicious: 70,
  supportedImpersonation: 35,
  brandMismatchFakeLogin: 40,
  sensitiveFormExternal: 30,
  deceptiveCredentialCollection: 25,
  multipleMaliciousScripts: 25,
  insecureHttp: 20,
  unusualImpersonation: 15,
  riskyFormDestination: 15,
  dynamicFormAction: 15,
  insecureFormAction: 12,
  missingCookieSecurity: 10,
  suspiciousScript: 10,
  punycodeHostname: 10,
  hiddenIframe: 15,
  atSymbolInUrl: 25,
  doubleSlashRedirect: 20,
  nonStandardPort: 20,
  httpsTokenInDomain: 25,
  domainAgeVeryYoung: 25,
  domainAgeYoung: 15,
  domainAgeModerate: 8,
  ctCertVeryYoung: 20,
  ctCertYoung: 10,
  missingSpfAndDmarc: 10,
  missingHstsAndCsp: 12,
  missingSecurityHeaders: 6,
  mixedContent: 8,
  significantTracking: 5,
  thirdPartyCookies: 3,
} as const;

export const CATEGORY_CAPS = {
  transport: 25,
  domain: 35,
  phishing: 75,
  content: 30,
  reputation: 100,
} as const;

export const DEFAULT_BLOCK_CATEGORIES: BlockCategories = {
  analytics: true,
  advertising: true,
  social: true,
  session_replay: true,
  fingerprinting: false,
};

export const DEFAULT_SETTINGS: Settings = {
  version: SETTINGS_VERSION,
  protectionMode: "standard",
  blockCategories: DEFAULT_BLOCK_CATEGORIES,
  strictExtra: false,
  cookieToolsEnabled: true,
  sensitiveFormWarnings: true,
  suspiciousScriptAlerts: true,
  autoScan: true,
  showLowConfidenceFindings: false,
  allowlist: [],
};

export const PROTECTION_MODES: { value: ProtectionMode; label: string; description: string }[] = [
  {
    value: "off",
    label: "Off",
    description: "No tracker requests are blocked. Detection and warnings stay available.",
  },
  {
    value: "standard",
    label: "Standard",
    description: "Blocks high-confidence analytics, advertising, social, and session-replay trackers.",
  },
  {
    value: "strict",
    label: "Strict",
    description:
      "Blocks all standard categories plus fingerprinting and aggressive extras. May break embeds, logins, or video.",
  },
  {
    value: "custom",
    label: "Custom",
    description: "Choose individual tracker categories and optionally add aggressive extra rules.",
  },
];

export const TRACKER_CATEGORY_LABELS: Record<TrackerCategory, string> = {
  analytics: "Analytics",
  advertising: "Advertising",
  social: "Social tracking",
  session_replay: "Session replay",
  fingerprinting: "Fingerprinting",
};

export const STRICT_RULESET_ID = "strict";
export const STANDARD_RULESET_IDS = ["analytics", "advertising", "social", "session_replay"];
export const ALL_RULESET_IDS = [
  "analytics",
  "advertising",
  "social",
  "session_replay",
  "fingerprinting",
  "strict",
] as const;

export const CATEGORY_TO_RULESET: Record<TrackerCategory, string> = {
  analytics: "analytics",
  advertising: "advertising",
  social: "social",
  session_replay: "session_replay",
  fingerprinting: "fingerprinting",
};

export const DNR_RULE_ID_BASE = 10000;
export const DNR_LAST_SYNC_KEY = "sentinel:dnr-synced:v1";

export const SUSPICIOUS_TLDS = new Set([
  "zip",
  "mov",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "work",
  "click",
  "country",
  "stream",
  "download",
  "review",
  "cricket",
  "science",
  "party",
  "gdn",
  "racing",
  "win",
  "bid",
  "loan",
  "men",
  "date",
  "faith",
  "kim",
  "quest",
  "rest",
  "monster",
  "sbs",
  "cyou",
  "top",
  "buzz",
  "icu",
]);

export const URL_SHORTENERS = new Set([
  "bit.ly",
  "t.co",
  "tinyurl.com",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "cut.tl",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
  "rebrand.ly",
  "tiny.cc",
  "lnkd.in",
  "t.ly",
  "short.gy",
  "s.id",
  "v.gd",
  "qr.ae",
  "u.to",
]);

export const LOGIN_TERMS = [
  "login",
  "log-in",
  "signin",
  "sign-in",
  "account",
  "accounts",
  "verify",
  "verification",
  "secure",
  "security",
  "auth",
  "authenticate",
  "password",
  "passwd",
  "support",
  "unlock",
  "recovery",
  "recover",
  "billing",
  "payment",
  "wallet",
  "update",
  "confirm",
  "session",
  "mfa",
  "otp",
];

export const SENSITIVE_TLDS_THAT_REQUIRE_CONTEXT = new Set(["xyz", "info", "online", "site", "website"]);

export const MAX_TEXT_FIELD = 500;
export const MAX_EVIDENCE_ITEMS = 12;
