import { parse } from "tldts";
import { toUnicode } from "punycode/";
import { BRANDS, HOSTING_DOMAINS, type BrandDefinition } from "../data/brands";
import { LOGIN_TERMS, SUSPICIOUS_TLDS, URL_SHORTENERS } from "../shared/constants";
import type { BrandImpersonation, UrlSignals } from "../shared/types";
import { sanitizeText } from "../shared/validation";

const CONFUSABLE_MAP: Record<string, string> = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "8": "b",
  "9": "g",
  $: "s",
  "@": "a",
  "\u0430": "a",
  "\u0435": "e",
  "\u043e": "o",
  "\u0440": "p",
  "\u0441": "c",
  "\u0445": "x",
  "\u0456": "i",
  "\u0458": "j",
  "\u0443": "y",
  "\u0455": "s",
  "\u04bb": "h",
  "\u0261": "g",
};

const SUSPICIOUS_EXTENSION = /\.(exe|scr|apk|msi|dmg|iso|vbs|bat|cmd|jar|hta)(?:[./]|$)/i;

function skeleton(value: string): string {
  return value
    .toLowerCase()
    .split("")
    .map((char) => CONFUSABLE_MAP[char] ?? char)
    .join("")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/[^a-z0-9]/g, "");
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const previous = new Array<number>(b.length + 1);
  const current = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j += 1) previous[j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    current[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(
        (previous[j] ?? 0) + 1,
        (current[j - 1] ?? 0) + 1,
        (previous[j - 1] ?? 0) + cost,
      );
    }
    for (let j = 0; j <= b.length; j += 1) previous[j] = current[j] ?? 0;
  }
  return previous[b.length] ?? Math.max(a.length, b.length);
}

function hasMixedScripts(hostname: string): boolean {
  let latin = false;
  let cyrillic = false;
  let greek = false;
  for (const char of hostname) {
    const code = char.codePointAt(0) ?? 0;
    if ((code >= 0x41 && code <= 0x24f) || (code >= 0x1e00 && code <= 0x1eff)) latin = true;
    else if (code >= 0x370 && code <= 0x3ff) greek = true;
    else if (code >= 0x400 && code <= 0x4ff) cyrillic = true;
  }
  return [latin, cyrillic, greek].filter(Boolean).length > 1;
}

function registrableLabel(domain: string): string {
  const parts = domain.split(".");
  if (parts.length <= 1) return domain;
  return parts[0] ?? domain;
}

function isOwnedByBrand(hostname: string, domain: string | null, brand: BrandDefinition): boolean {
  if (!domain) return false;
  if (brand.domains.some((owned) => domain === owned || hostname.endsWith(`.${owned}`))) return true;
  const hosting = HOSTING_DOMAINS.some((host) => domain === host || hostname.endsWith(`.${host}`));
  if (hosting) {
    return brand.domains.some((owned) => hostname === owned || hostname.endsWith(`.${owned}`));
  }
  return false;
}

interface ChunkCandidate {
  method: BrandImpersonation["method"];
  distance: number | null;
  chunk: string;
}

function inspectChunks(
  brand: BrandDefinition,
  domain: string,
  unicodeDomain: string,
  hasLoginTerm: boolean,
): ChunkCandidate | null {
  const label = registrableLabel(unicodeDomain || domain).toLowerCase();
  const chunks = [label, ...label.split(/[-_]+/)].filter(Boolean);
  const brandSkeletons = brand.tokens.map((token) => ({
    token,
    skel: skeleton(token),
  }));

  let best: ChunkCandidate | null = null;
  const methodRank: Record<BrandImpersonation["method"], number> = {
    punycode: 4,
    lookalike: 3,
    token: 2,
    subdomain: 1,
  };

  const consider = (candidate: ChunkCandidate) => {
    if (!best || methodRank[candidate.method] > methodRank[best.method]) best = candidate;
  };

  for (const chunk of chunks) {
    const chunkSkel = skeleton(chunk);
    if (!chunkSkel) continue;
    for (const { token, skel } of brandSkeletons) {
      if (chunk === token) {
        consider({ method: "token", distance: 0, chunk });
        continue;
      }
      if (chunkSkel === skel && skel.length >= 5) {
        // eslint-disable-next-line no-control-regex
        const isUnicode = /[^\u0000-\u007f]/.test(chunk);
        consider({
          method: isUnicode || chunk.includes("xn--") ? "punycode" : "lookalike",
          distance: 0,
          chunk,
        });
        continue;
      }
      if (skel.length >= 5 && chunkSkel.length >= skel.length - 1 && chunkSkel.length <= skel.length + 2) {
        const distance = levenshtein(chunkSkel, skel);
        if (distance === 1) {
          // eslint-disable-next-line no-control-regex
          const isUnicode = /[^\u0000-\u007f]/.test(chunk);
          consider({
            method: isUnicode || chunk.includes("xn--") ? "punycode" : "lookalike",
            distance,
            chunk,
          });
        }
      }
    }
  }

  if (!best && hasLoginTerm) {
    const labels = unicodeDomain.toLowerCase().split(".");
    for (const token of brand.tokens) {
      if (labels.some((part) => part === token)) {
        consider({ method: "subdomain", distance: 0, chunk: token });
        break;
      }
    }
  }

  return best;
}

function findLoginTerms(hostname: string, path: string): string[] {
  const haystack = `${hostname} ${path}`.toLowerCase();
  return LOGIN_TERMS.filter((term) => haystack.includes(term));
}

export function emptyUrlSignals(input = ""): UrlSignals {
  return {
    input: sanitizeText(input, 2048),
    normalizedUrl: null,
    hostname: null,
    registrableDomain: null,
    publicSuffix: null,
    subdomain: null,
    protocol: "other",
    path: "",
    isIpAddress: false,
    isPunycode: false,
    unicodeHostname: null,
    hasMixedScripts: false,
    hasEmbeddedCredentials: false,
    isShortener: false,
    hasSuspiciousTld: false,
    hasLoginTerm: false,
    loginTerms: [],
    labelCount: 0,
    urlLength: 0,
    usesEncoding: false,
    suspiciousFileExtension: false,
    brandImpersonation: [],
    hostingPlatform: false,
    indicators: [],
    hasAtSymbol: false,
    hasDoubleSlashRedirect: false,
    hasNonStandardPort: false,
    hasHttpsInHostname: false,
  };
}

/** Pure URL analysis. Accepts only http(s) URLs; never fetches anything. */
export function analyzeUrl(rawUrl: string): UrlSignals {
  const base = emptyUrlSignals(rawUrl);
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return base;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ...base, protocol: "other", indicators: ["unsupported-protocol"] };
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  const parsed = parse(hostname, { allowPrivateDomains: true, detectIp: true });
  const domain = parsed.domain ?? (parsed.isIp ? hostname : null);
  const isPunycode = hostname.includes("xn--");
  let unicodeHostname = hostname;
  if (isPunycode) {
    try {
      unicodeHostname = toUnicode(hostname);
    } catch {
      unicodeHostname = hostname;
    }
  }
  const path = url.pathname;
  const loginTerms = findLoginTerms(hostname, path);
  const hasLoginTerm = loginTerms.length > 0;
  const publicSuffix = parsed.publicSuffix ?? null;
  const hostingPlatform = Boolean(
    domain && HOSTING_DOMAINS.some((host) => domain === host || hostname.endsWith(`.${host}`)),
  );

  const impersonation: BrandImpersonation[] = [];
  if (domain && !parsed.isIp) {
    for (const brand of BRANDS) {
      if (isOwnedByBrand(hostname, domain, brand)) continue;
      const candidate = inspectChunks(brand, domain, unicodeHostname, hasLoginTerm);
      if (!candidate) continue;
      if (hostingPlatform && candidate.method === "token") continue;
      impersonation.push({
        brandId: brand.id,
        brandName: brand.name,
        observedDomain: domain,
        method: candidate.method,
        hasLoginTerm,
        distance: candidate.distance,
        explanation:
          candidate.method === "lookalike" || candidate.method === "punycode"
            ? `The label “${sanitizeText(candidate.chunk, 60)}” closely resembles the brand “${brand.name}” but is not one of its known domains.`
            : candidate.method === "subdomain"
              ? `The brand name “${brand.name}” appears in a subdomain of an unrelated registrable domain.`
              : `The brand name “${brand.name}” appears in an unrelated registrable domain.`,
      });
    }
  }

  const indicators: string[] = [];
  if (parsed.isIp) indicators.push("ip-address-host");
  if (isPunycode) indicators.push("punycode-host");
  if (hasMixedScripts(unicodeHostname)) indicators.push("mixed-script-host");
  if (url.username || url.password) indicators.push("embedded-credentials");
  if (domain && URL_SHORTENERS.has(domain)) indicators.push("url-shortener");
  if (publicSuffix && SUSPICIOUS_TLDS.has(publicSuffix)) indicators.push("suspicious-tld");
  if (rawUrl.length > 120) indicators.push("long-url");
  if (hostname.split(".").length > 4) indicators.push("many-subdomains");
  if (/%[0-9a-f]{2}/i.test(url.pathname + url.search)) indicators.push("encoded-characters");
  if (hasLoginTerm) indicators.push("login-terms");
  if (impersonation.some((item) => item.method === "lookalike" || item.method === "punycode")) {
    indicators.push("brand-lookalike");
  }
  if (impersonation.some((item) => item.method === "token")) indicators.push("brand-token");
  const hasAtSymbol = rawUrl.includes("@");
  const hasDoubleSlashRedirect = /https?:\/\/[^/]+\/\//.test(rawUrl);
  const hasNonStandardPort = Boolean(url.port && !["80", "443", ""].includes(url.port));
  const hasHttpsInHostname = hostname.split(".").some((part) => part.includes("https-") || part.includes("-https") || (part.startsWith("https") && part.length > 5));

  if (hasAtSymbol) indicators.push("at-symbol-in-url");
  if (hasDoubleSlashRedirect) indicators.push("double-slash-redirect");
  if (hasNonStandardPort) indicators.push("non-standard-port");
  if (hasHttpsInHostname) indicators.push("https-token-in-hostname");

  return {
    ...base,
    normalizedUrl: `${url.protocol}//${url.host}${path}`,
    hostname,
    registrableDomain: domain,
    publicSuffix,
    subdomain: parsed.subdomain || null,
    protocol: url.protocol === "https:" ? "https:" : "http:",
    path,
    isIpAddress: Boolean(parsed.isIp),
    isPunycode,
    unicodeHostname,
    hasMixedScripts: hasMixedScripts(unicodeHostname),
    hasEmbeddedCredentials: Boolean(url.username || url.password),
    isShortener: Boolean(domain && URL_SHORTENERS.has(domain)),
    hasSuspiciousTld: Boolean(publicSuffix && SUSPICIOUS_TLDS.has(publicSuffix)),
    hasLoginTerm,
    loginTerms,
    labelCount: hostname.split(".").length,
    urlLength: rawUrl.length,
    usesEncoding: /%[0-9a-f]{2}/i.test(url.pathname + url.search),
    suspiciousFileExtension: SUSPICIOUS_EXTENSION.test(path),
    brandImpersonation: impersonation,
    hostingPlatform,
    indicators,
    hasAtSymbol,
    hasDoubleSlashRedirect,
    hasNonStandardPort,
    hasHttpsInHostname,
  };
}
