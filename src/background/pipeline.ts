import { analyzeConnection } from "../security/connection-analyzer";
import { analyzeCookies } from "../security/cookie-analyzer";
import { analyzeDomainIntel } from "../security/domain-intel";
import { analyzeForms } from "../security/form-analyzer";
import { analyzeSecurityHeaders } from "../security/header-analyzer";
import { detectPhishing } from "../security/phishing-detector";
import { LocalReputationProvider, ReputationService, UrlScanReputationProvider } from "../security/reputation";
import { analyzeScripts } from "../security/script-analyzer";
import { analyzeTrackers } from "../security/tracker-detector";
import { assessWebsite } from "../security/trust-score";
import { analyzeUrl } from "../security/url-analyzer";
import { reputationCache } from "./reputation-cache";
import { getBlockedRecentCount, getProtectionStatus } from "../browser/network-rules";
import { getCookiesForUrl } from "../browser/cookies";
import { getPermissionState } from "../browser/permissions";
import { getTab, isAssessableUrl, requestPageEvidence, setBadge } from "../browser/tabs";
import { recordAssessment } from "../storage/history";
import { getDeletedCookieCount, getSettings, isAllowlisted } from "../storage/settings";
import { saveSnapshot } from "../storage/snapshots";
import type { PageEvidence, TabSnapshot, TrustAssessment } from "../shared/types";
import { sanitizePageEvidence, sanitizeText } from "../shared/validation";
import { classificationLabel } from "../security/risk-classifier";

const reputation = new ReputationService(
  [new LocalReputationProvider(), new UrlScanReputationProvider()],
  reputationCache,
);

interface EvidenceCacheEntry {
  evidence: PageEvidence;
  receivedAt: number;
}

const evidenceCache = new Map<number, EvidenceCacheEntry>();
const inflight = new Map<number, Promise<TabSnapshot>>();
const evidenceRevision = new Map<number, number>();

export function cacheEvidence(tabId: number, raw: unknown): PageEvidence | null {
  const evidence = sanitizePageEvidence(raw);
  if (!evidence) return null;
  evidenceCache.set(tabId, { evidence, receivedAt: Date.now() });
  evidenceRevision.set(tabId, (evidenceRevision.get(tabId) ?? 0) + 1);
  return evidence;
}

export function clearTabCache(tabId: number): void {
  evidenceCache.delete(tabId);
  evidenceRevision.delete(tabId);
}

export function getCachedEvidence(tabId: number): PageEvidence | null {
  return evidenceCache.get(tabId)?.evidence ?? null;
}

export interface AssessTabOptions {
  force?: boolean;
  evidenceOverride?: PageEvidence | null;
}

async function buildSnapshot(tabId: number, options: AssessTabOptions): Promise<TabSnapshot> {
  const tab = await getTab(tabId);
  if (!tab || !tab.url) throw new Error("The tab is no longer available.");

  const url = tab.url;
  const now = Date.now();
  const revisionAtStart = evidenceRevision.get(tabId) ?? 0;
  const settings = await getSettings();
  const signals = analyzeUrl(url);
  const pageHost = signals.hostname;
  const allowlisted = isAllowlisted(settings, pageHost);

  let evidence = options.evidenceOverride ?? null;
  let contentScriptAvailable = false;

  if (!evidence && isAssessableUrl(url)) {
    const cached = evidenceCache.get(tabId);
    if (!options.force && cached && now - cached.receivedAt < 12_000) {
      evidence = cached.evidence;
      contentScriptAvailable = true;
    } else {
      const result = await requestPageEvidence(tabId);
      evidence = result.evidence;
      contentScriptAvailable = result.contentScript;
      if (evidence) cacheEvidence(tabId, evidence);
    }
  }

  const origin = signals.normalizedUrl ? `${signals.protocol}//${signals.hostname}` : null;
  const assessable = isAssessableUrl(url) && Boolean(origin);

  const [
    cookieResult,
    reputationResult,
    blockedRecent,
    permissionState,
    protection,
    domainIntelReport,
    headersReport,
  ] = await Promise.all([
    assessable ? getCookiesForUrl(url) : Promise.resolve({ cookies: null, reason: "Unsupported page type." }),
    reputation.lookup(signals.registrableDomain ?? pageHost),
    assessable ? getBlockedRecentCount(tabId) : Promise.resolve(null),
    getPermissionState(origin, contentScriptAvailable),
    getProtectionStatus(settings, allowlisted),
    assessable ? analyzeDomainIntel(signals.registrableDomain ?? pageHost) : Promise.resolve(undefined),
    assessable && origin ? analyzeSecurityHeaders(origin) : Promise.resolve(undefined),
  ]);

  const phishing = detectPhishing(signals, evidence, reputationResult.matches);
  const forms = analyzeForms(evidence?.forms ?? null, { pageUrl: url });
  const credentialForm = Boolean(
    evidence &&
      (evidence.passwordFieldCount > 0 ||
        evidence.forms.some((form) => form.hasPassword || form.hasOtp || form.hasCard || form.hasNationalId)),
  );
  const scripts = analyzeScripts(evidence, { credentialForm, phishingScore: phishing.riskScore });
  const trackers = analyzeTrackers(evidence?.resources ?? null, url, { blockedRecent });
  const deletedThisSession = await getDeletedCookieCount();
  const cookies = analyzeCookies(cookieResult.cookies, isAssessableUrl(url) ? url : "https://invalid.example/", now, {
    reason: cookieResult.reason,
    deletedThisSession,
  });
  const connection = analyzeConnection(url, evidence, assessable);

  const assessment = assessWebsite({
    url,
    signals,
    connection,
    phishing,
    page: evidence,
    forms,
    scripts,
    cookies,
    trackers,
    reputation: reputationResult,
    headers: headersReport,
    domainIntel: domainIntelReport,
    now,
  });

  const snapshot: TabSnapshot = {
    tabId,
    url,
    domain: assessment.domain,
    title: sanitizeText(tab.title ?? evidence?.title ?? "", 200),
    fetchedAt: now,
    assessment,
    connection,
    forms,
    scripts,
    cookies,
    trackers,
    protection,
    permissions: permissionState,
    allowlisted,
    evidence,
    pageEvidenceAvailable: Boolean(evidence),
    headers: headersReport,
    domainIntel: domainIntelReport,
  };

  // A content-script update may have arrived while the slower network signals
  // were being collected. Do not persist or return a snapshot built from an
  // older page observation when a newer assessment can be requested instead.
  if (revisionAtStart !== (evidenceRevision.get(tabId) ?? 0) && !options.evidenceOverride) {
    return buildSnapshot(tabId, { ...options, force: true });
  }

  await saveSnapshot(snapshot);
  if (assessable) {
    await recordAssessment(assessment, now).catch(() => undefined);
  }
  await updateBadge(tabId, assessment, allowlisted);
  return snapshot;
}

async function updateBadge(tabId: number, assessment: TrustAssessment, allowlisted: boolean): Promise<void> {
  if (allowlisted) {
    await setBadge(tabId, "—", "#334155", "Sentinel: this site is allowlisted; warnings and blocking are disabled.");
    return;
  }
  const score = assessment.score;
  const text = score === null ? "?" : String(score);
  const color =
    assessment.classification === "safe"
      ? "#0f9f6e"
      : assessment.classification === "caution"
        ? "#b45309"
        : assessment.classification === "dangerous"
          ? "#b91c1c"
          : "#475569";
  await setBadge(tabId, text, color, `Sentinel: ${classificationLabel(assessment.classification)}${score === null ? "" : ` (${score}/100)`}`);
}

export async function assessTab(tabId: number, options: AssessTabOptions = {}): Promise<TabSnapshot> {
  const existing = inflight.get(tabId);
  if (existing) return existing;
  const promise = buildSnapshot(tabId, options).finally(() => {
    inflight.delete(tabId);
  });
  inflight.set(tabId, promise);
  return promise;
}

/** Builds an honest "unknown" assessment for a tab that cannot be inspected. */
export async function assessUnsupportedTab(tabId: number): Promise<TabSnapshot> {
  return assessTab(tabId, { force: true });
}
