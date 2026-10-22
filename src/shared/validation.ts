import { parse } from "tldts";
import {
  COOKIE_LIMIT,
  DEFAULT_SETTINGS,
  EVIDENCE_FORM_LIMIT,
  EVIDENCE_RESOURCE_LIMIT,
  EVIDENCE_SCRIPT_LIMIT,
  HISTORY_LIMIT,
  SETTINGS_VERSION,
  TEXT_LIMIT,
} from "./constants";
import type {
  BlockCategories,
  CookieSnapshot,
  FormMetadata,
  ObservedResource,
  PageEvidence,
  ScriptMetadata,
  Settings,
} from "./types";

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e]/g;

export function sanitizeText(value: unknown, max = TEXT_LIMIT): string {
  if (typeof value !== "string") return "";
  const clean = value.replace(CONTROL_CHARS, "").trim();
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

/** Removes credentials, query strings and fragments before anything is stored. */
export function sanitizeUrl(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 4096) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return null;
  }
}

export function sanitizeHostname(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const host = value.trim().toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253) return null;
  if (!/^[a-z0-9.-]+$/.test(host) && !host.includes("xn--")) return null;
  if (host.includes("..") || host.startsWith(".") || host.endsWith(".")) return null;
  return host;
}

export function registrableDomainOf(value: string): string | null {
  const parsed = parse(value, { allowPrivateDomains: true, detectIp: true });
  if (parsed.isIp) return parsed.hostname ?? null;
  return parsed.domain ?? null;
}

export function isValidHostname(value: string): boolean {
  const host = sanitizeHostname(value);
  if (!host) return false;
  const parsed = parse(host, { allowPrivateDomains: true, detectIp: true });
  return Boolean(parsed.hostname) || Boolean(parsed.isIp);
}

/** Validates a user-supplied allowlist entry. Only registrable domains are accepted. */
export function normalizeAllowlistDomain(value: unknown): string | null {
  if (typeof value !== "string") return null;
  let candidate = value.trim().toLowerCase();
  if (!candidate) return null;
  if (candidate.includes("://")) {
    try {
      candidate = new URL(candidate).hostname;
    } catch {
      return null;
    }
  }
  candidate = candidate.replace(/^\*\./, "").replace(/\/.*$/, "").replace(/\.$/, "");
  if (candidate.length > 253 || candidate.includes(" ")) return null;
  if (!/^[a-z0-9.-]+$/.test(candidate)) return null;
  const parsed = parse(candidate, { allowPrivateDomains: true, detectIp: true });
  if (parsed.isIp) return candidate;
  if (!parsed.domain || parsed.domain !== candidate) return null;
  if (!parsed.publicSuffix) return null;
  return candidate;
}

function sanitizeBlockCategories(value: unknown): BlockCategories {
  const source = (value ?? {}) as Record<string, unknown>;
  const pick = (key: keyof BlockCategories): boolean =>
    typeof source[key] === "boolean" ? (source[key] as boolean) : DEFAULT_SETTINGS.blockCategories[key];
  return {
    analytics: pick("analytics"),
    advertising: pick("advertising"),
    social: pick("social"),
    session_replay: pick("session_replay"),
    fingerprinting: pick("fingerprinting"),
  };
}

export function normalizeSettings(value: unknown): Settings {
  const source = (value ?? {}) as Record<string, unknown>;
  const mode = source.protectionMode;
  const protectionMode =
    mode === "off" || mode === "standard" || mode === "strict" || mode === "custom"
      ? mode
      : DEFAULT_SETTINGS.protectionMode;
  const allowlistRaw = Array.isArray(source.allowlist) ? source.allowlist : [];
  const allowlist = Array.from(
    new Set(
      allowlistRaw
        .map((item) => normalizeAllowlistDomain(item))
        .filter((item): item is string => Boolean(item)),
    ),
  ).slice(0, 200);

  return {
    version: SETTINGS_VERSION,
    protectionMode,
    blockCategories: sanitizeBlockCategories(source.blockCategories),
    strictExtra: source.strictExtra === true,
    cookieToolsEnabled: source.cookieToolsEnabled !== false,
    sensitiveFormWarnings: source.sensitiveFormWarnings !== false,
    suspiciousScriptAlerts: source.suspiciousScriptAlerts !== false,
    autoScan: source.autoScan !== false,
    showLowConfidenceFindings: source.showLowConfidenceFindings === true,
    allowlist,
  };
}

/* ------------------------------- evidence -------------------------------- */

function asString(value: unknown, max = TEXT_LIMIT): string {
  return sanitizeText(value, max);
}

function asBoolean(value: unknown): boolean {
  return value === true;
}

function asCount(value: unknown, max: number): number {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.max(0, Math.min(max, Math.floor(value)))
    : 0;
}

const FIELD_KINDS = new Set([
  "password",
  "email",
  "username",
  "otp",
  "card",
  "security-code",
  "national-id",
]);

function sanitizeFieldKinds(value: unknown): PageEvidence["forms"][number]["fieldKinds"] {
  if (!Array.isArray(value)) return [];
  const kinds = value.filter(
    (item): item is PageEvidence["forms"][number]["fieldKinds"][number] =>
      typeof item === "string" && FIELD_KINDS.has(item),
  );
  return Array.from(new Set(kinds));
}

export function sanitizeFormMetadata(value: unknown): FormMetadata | null {
  if (typeof value !== "object" || value === null) return null;
  const raw = value as Record<string, unknown>;
  const action = sanitizeUrl(raw.action);
  const actionHost = sanitizeHostname(raw.actionHost);
  const fieldsRaw = Array.isArray(raw.fields) ? raw.fields : [];
  const fields = fieldsRaw
    .slice(0, 40)
    .map((field) => {
      if (typeof field !== "object" || field === null) return null;
      const f = field as Record<string, unknown>;
      const kind = typeof f.kind === "string" && FIELD_KINDS.has(f.kind) ? f.kind : null;
      if (!kind) return null;
      return {
        kind: kind as PageEvidence["forms"][number]["fields"][number]["kind"],
        fieldType: asString(f.fieldType, 30),
        autocomplete: typeof f.autocomplete === "string" ? asString(f.autocomplete, 60) : null,
        hasLabel: asBoolean(f.hasLabel),
      };
    })
    .filter((field): field is NonNullable<typeof field> => Boolean(field));
  const submit = raw.submitControl;

  return {
    index: asCount(raw.index, 1000),
    action,
    actionHost,
    actionMissing: asBoolean(raw.actionMissing),
    actionIsJavascript: asBoolean(raw.actionIsJavascript),
    actionChanged: asBoolean(raw.actionChanged),
    method: asString(raw.method, 10).toUpperCase() || "GET",
    target: typeof raw.target === "string" ? asString(raw.target, 60) : null,
    hasPassword: asBoolean(raw.hasPassword),
    hasSensitive: asBoolean(raw.hasSensitive),
    hasOtp: asBoolean(raw.hasOtp),
    hasCard: asBoolean(raw.hasCard),
    hasNationalId: asBoolean(raw.hasNationalId),
    hasHiddenFields: asBoolean(raw.hasHiddenFields),
    fieldKinds: sanitizeFieldKinds(raw.fieldKinds),
    fields,
    submitControl: submit === "button" || submit === "input" ? submit : "none",
    inlineSubmitHandler: asBoolean(raw.inlineSubmitHandler),
  };
}

const PATTERN_IDS = new Set([
  "eval-call",
  "atob-call",
  "from-char-code",
  "document-write",
  "unescape-call",
  "hex-escape-density",
  "long-base64",
  "clipboard-listener",
  "keyboard-listener",
  "form-action-write",
  "location-write",
  "dynamic-script-create",
  "inline-handler",
]);

export function sanitizeScriptMetadata(value: unknown): ScriptMetadata | null {
  if (typeof value !== "object" || value === null) return null;
  const raw = value as Record<string, unknown>;
  const patterns = Array.isArray(raw.patterns)
    ? raw.patterns
        .slice(0, 12)
        .map((pattern) => {
          if (typeof pattern !== "object" || pattern === null) return null;
          const p = pattern as Record<string, unknown>;
          if (typeof p.id !== "string" || !PATTERN_IDS.has(p.id)) return null;
          const confidence = p.confidence;
          return {
            id: p.id as ScriptMetadata["patterns"][number]["id"],
            label: asString(p.label, 80),
            count: asCount(p.count, 10000),
            confidence: (
              confidence === "high" || confidence === "medium" || confidence === "low"
                ? confidence
                : "low") as ScriptMetadata["patterns"][number]["confidence"],
          };
        })
        .filter((pattern): pattern is NonNullable<typeof pattern> => Boolean(pattern))
    : [];

  return {
    src: sanitizeUrl(raw.src),
    host: sanitizeHostname(raw.host),
    firstParty: asBoolean(raw.firstParty),
    inline: asBoolean(raw.inline),
    inlineLength: asCount(raw.inlineLength, 5_000_000),
    patterns,
  };
}

export function sanitizeObservedResource(value: unknown): ObservedResource | null {
  if (typeof value !== "object" || value === null) return null;
  const raw = value as Record<string, unknown>;
  const host = sanitizeHostname(raw.host);
  const url = sanitizeUrl(raw.url);
  if (!host || !url) return null;
  return {
    host,
    url,
    type: asString(raw.type, 30) || "other",
    count: Math.max(1, asCount(raw.count, 10000)),
    firstParty: asBoolean(raw.firstParty),
  };
}

export function sanitizePageEvidence(value: unknown): PageEvidence | null {
  if (typeof value !== "object" || value === null) return null;
  const raw = value as Record<string, unknown>;
  const url = sanitizeUrl(raw.url);
  const origin = sanitizeUrl(raw.origin);
  if (!url || !origin) return null;

  const forms = (Array.isArray(raw.forms) ? raw.forms : [])
    .slice(0, EVIDENCE_FORM_LIMIT)
    .map(sanitizeFormMetadata)
    .filter((form): form is FormMetadata => Boolean(form));
  const scripts = (Array.isArray(raw.scripts) ? raw.scripts : [])
    .slice(0, EVIDENCE_SCRIPT_LIMIT)
    .map(sanitizeScriptMetadata)
    .filter((script): script is ScriptMetadata => Boolean(script));
  const resources = (Array.isArray(raw.resources) ? raw.resources : [])
    .slice(0, EVIDENCE_RESOURCE_LIMIT)
    .map(sanitizeObservedResource)
    .filter((resource): resource is ObservedResource => Boolean(resource));

  const handlerKinds = new Set([
    "password",
    "email",
    "username",
    "otp",
    "card",
    "security-code",
    "national-id",
  ]);
  const sensitiveInputHandlers = (Array.isArray(raw.sensitiveInputHandlers)
    ? raw.sensitiveInputHandlers
    : [])
    .slice(0, 40)
    .map((handler) => {
      if (typeof handler !== "object" || handler === null) return null;
      const h = handler as Record<string, unknown>;
      if (typeof h.kind !== "string" || !handlerKinds.has(h.kind)) return null;
      return {
        kind: h.kind as PageEvidence["sensitiveInputHandlers"][number]["kind"],
        handler: asString(h.handler, 40),
      };
    })
    .filter((handler): handler is NonNullable<typeof handler> => Boolean(handler));

  return {
    url,
    origin,
    title: asString(raw.title, 200),
    isTopFrame: asBoolean(raw.isTopFrame),
    collectedAt: asCount(raw.collectedAt, Number.MAX_SAFE_INTEGER),
    forms,
    scripts,
    resources,
    mixedContentCount: asCount(raw.mixedContentCount, 10000),
    mixedContentExamples: Array.isArray(raw.mixedContentExamples)
      ? raw.mixedContentExamples
          .slice(0, 8)
          .map((item) => sanitizeUrl(item))
          .filter((item): item is string => Boolean(item))
      : [],
    sensitiveInputCount: asCount(raw.sensitiveInputCount, 10000),
    passwordFieldCount: asCount(raw.passwordFieldCount, 10000),
    sensitiveInputHandlers,
    clipboardHandlerIndicators: Array.isArray(raw.clipboardHandlerIndicators)
      ? raw.clipboardHandlerIndicators.slice(0, 20).map((item) => asString(item, 80))
      : [],
    suspiciousOverlay: asBoolean(raw.suspiciousOverlay),
    suspiciousOverlayEvidence: Array.isArray(raw.suspiciousOverlayEvidence)
      ? raw.suspiciousOverlayEvidence.slice(0, 8).map((item) => asString(item, 160))
      : [],
    iframeCount: asCount(raw.iframeCount, 10000),
    hiddenIframeCount: asCount(raw.hiddenIframeCount, 10000),
    hiddenIframeExamples: Array.isArray(raw.hiddenIframeExamples)
      ? raw.hiddenIframeExamples.slice(0, 8).map((item) => sanitizeUrl(item)).filter((item): item is string => Boolean(item))
      : [],
    brandMismatchDetected: asBoolean(raw.brandMismatchDetected),
    brandMismatchBrand: raw.brandMismatchBrand ? asString(raw.brandMismatchBrand, 100) : null,
    brandMismatchEvidence: Array.isArray(raw.brandMismatchEvidence)
      ? raw.brandMismatchEvidence.slice(0, 8).map((item) => asString(item, 200))
      : [],
    limitations: Array.isArray(raw.limitations)
      ? raw.limitations.slice(0, 8).map((item) => asString(item, 200))
      : [],
  };
}

export function sanitizeCookie(value: unknown): CookieSnapshot | null {
  if (typeof value !== "object" || value === null) return null;
  const raw = value as Record<string, unknown>;
  const name = asString(raw.name, 200);
  const domain = sanitizeHostname(raw.domain);
  if (!name || !domain) return null;
  const sameSite = raw.sameSite;
  const firstParty = raw.firstParty;
  return {
    name,
    domain,
    path: asString(raw.path, 300) || "/",
    secure: asBoolean(raw.secure),
    httpOnly: asBoolean(raw.httpOnly),
    sameSite:
      sameSite === "no_restriction" || sameSite === "lax" || sameSite === "strict"
        ? sameSite
        : "unspecified",
    session: asBoolean(raw.session),
    expirationDate:
      typeof raw.expirationDate === "number" && Number.isFinite(raw.expirationDate)
        ? raw.expirationDate
        : null,
    hostOnly: asBoolean(raw.hostOnly),
    storeId: asString(raw.storeId, 80) || "0",
    firstParty: typeof firstParty === "boolean" ? firstParty : null,
  };
}

export function sanitizeCookieList(value: unknown): CookieSnapshot[] {
  if (!Array.isArray(value)) return [];
  return value
    .slice(0, COOKIE_LIMIT)
    .map(sanitizeCookie)
    .filter((cookie): cookie is CookieSnapshot => Boolean(cookie));
}

export function sanitizeHistory(value: unknown): { domain: string; score: number | null; classification: string; critical: boolean; findingCounts: Record<string, number>; assessedAt: number }[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, HISTORY_LIMIT).flatMap((entry) => {
    if (typeof entry !== "object" || entry === null) return [];
    const raw = entry as Record<string, unknown>;
    const domain = sanitizeHostname(raw.domain);
    if (!domain) return [];
    const classification = raw.classification;
    const valid =
      classification === "safe" ||
      classification === "caution" ||
      classification === "dangerous" ||
      classification === "unknown";
    if (!valid) return [];
    const counts: Record<string, number> = {};
    if (typeof raw.findingCounts === "object" && raw.findingCounts !== null) {
      for (const [key, count] of Object.entries(raw.findingCounts as Record<string, unknown>)) {
        if (typeof count === "number" && Number.isFinite(count)) counts[asString(key, 30)] = asCount(count, 10000);
      }
    }
    return [
      {
        domain,
        score:
          typeof raw.score === "number" && Number.isFinite(raw.score)
            ? Math.max(0, Math.min(100, Math.round(raw.score)))
            : null,
        classification,
        critical: raw.critical === true,
        findingCounts: counts,
        assessedAt: asCount(raw.assessedAt, Number.MAX_SAFE_INTEGER),
      },
    ];
  });
}
