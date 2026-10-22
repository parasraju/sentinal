export type Classification = "safe" | "caution" | "dangerous" | "unknown";
export type Confidence = "low" | "medium" | "high";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type FindingCategory =
  | "connection"
  | "phishing"
  | "domain"
  | "form"
  | "script"
  | "cookie"
  | "tracker"
  | "reputation"
  | "header"
  | "dns"
  | "content"
  | "permission";

export type FindingSource =
  | "local-heuristic"
  | "local-list"
  | "reputation-feed"
  | "observed"
  | "browser";

export interface SecurityFinding {
  /** Stable rule identity. Reused across pages so findings can be aggregated. */
  id: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  title: string;
  explanation: string;
  evidence: string[];
  remediation: string;
  source: FindingSource;
  /** Points deducted from the baseline score. 0 means informational. */
  penalty: number;
}

export type EvidenceCompleteness = "full" | "partial" | "url-only";

export interface TrustAssessment {
  domain: string;
  score: number | null;
  classification: Classification;
  confidence: Confidence;
  confidenceScore?: number;
  findings: SecurityFinding[];
  assessedAt: number;
  assessmentVersion: string;
  /** True when high-confidence credential theft evidence exists. */
  critical: boolean;
  /** Short human-readable descriptions of the main score drivers. */
  topFactors: string[];
  limitations: string[];
  evidenceCompleteness: EvidenceCompleteness;
}

/* ------------------------------------------------------------------ URL ---- */

export interface BrandImpersonation {
  brandId: string;
  brandName: string;
  observedDomain: string;
  method: "token" | "lookalike" | "punycode" | "subdomain";
  hasLoginTerm: boolean;
  distance: number | null;
  explanation: string;
}

export interface UrlSignals {
  input: string;
  normalizedUrl: string | null;
  hostname: string | null;
  registrableDomain: string | null;
  publicSuffix: string | null;
  subdomain: string | null;
  protocol: "http:" | "https:" | "other";
  path: string;
  isIpAddress: boolean;
  isPunycode: boolean;
  unicodeHostname: string | null;
  hasMixedScripts: boolean;
  hasEmbeddedCredentials: boolean;
  isShortener: boolean;
  hasSuspiciousTld: boolean;
  hasLoginTerm: boolean;
  loginTerms: string[];
  labelCount: number;
  urlLength: number;
  usesEncoding: boolean;
  suspiciousFileExtension: boolean;
  brandImpersonation: BrandImpersonation[];
  hostingPlatform: boolean;
  indicators: string[];
  hasAtSymbol: boolean;
  hasDoubleSlashRedirect: boolean;
  hasNonStandardPort: boolean;
  hasHttpsInHostname: boolean;
}

/* ------------------------------------------------------------ connection --- */

export type ConnectionStatus =
  | "secure"
  | "insecure"
  | "unavailable"
  | "browser-handled";

export interface ConnectionInfo {
  protocol: "http:" | "https:" | "other";
  status: ConnectionStatus;
  secure: boolean;
  mixedContentCount: number;
  mixedContentExamples: string[];
  explanation: string;
  limitations: string[];
}

/* ----------------------------------------------------------------- forms --- */

export type SensitiveFieldKind =
  | "password"
  | "email"
  | "username"
  | "otp"
  | "card"
  | "security-code"
  | "national-id";

export interface FormFieldMeta {
  kind: SensitiveFieldKind;
  fieldType: string;
  autocomplete: string | null;
  hasLabel: boolean;
}

export interface FormMetadata {
  index: number;
  /** Sanitized resolved action (no query, no credentials). */
  action: string | null;
  actionHost: string | null;
  actionMissing: boolean;
  actionIsJavascript: boolean;
  actionChanged: boolean;
  method: string;
  target: string | null;
  hasPassword: boolean;
  hasSensitive: boolean;
  hasOtp: boolean;
  hasCard: boolean;
  hasNationalId: boolean;
  hasHiddenFields: boolean;
  fieldKinds: SensitiveFieldKind[];
  fields: FormFieldMeta[];
  submitControl: "button" | "input" | "none";
  inlineSubmitHandler: boolean;
}

export type FormRelationship = "same-origin" | "cross-origin" | "unknown" | "insecure";

export type FormFlag =
  | "same-origin"
  | "cross-origin-external"
  | "trusted-provider"
  | "insecure-action"
  | "get-sensitive"
  | "action-changed"
  | "action-javascript"
  | "action-missing"
  | "external-sensitive"
  | "external-account"
  | "destination-unknown";

export interface FormAnalysis {
  formIndex: number;
  pageOrigin: string;
  destinationOrigin: string | null;
  destinationHost: string | null;
  relationship: FormRelationship;
  trustedProvider: string | null;
  sensitiveKinds: SensitiveFieldKind[];
  risk: "none" | "low" | "medium" | "high" | "critical";
  confidence: Confidence;
  reasons: string[];
  limitations: string[];
  requiresVerification: boolean;
  flags: FormFlag[];
}

/* --------------------------------------------------------------- scripts --- */

export type ScriptPatternId =
  | "eval-call"
  | "atob-call"
  | "from-char-code"
  | "document-write"
  | "unescape-call"
  | "hex-escape-density"
  | "long-base64"
  | "clipboard-listener"
  | "keyboard-listener"
  | "form-action-write"
  | "location-write"
  | "dynamic-script-create"
  | "inline-handler";

export interface ScriptPatternHit {
  id: ScriptPatternId;
  label: string;
  count: number;
  confidence: Confidence;
}

export interface ScriptMetadata {
  /** Sanitized: origin + path only, no query or credentials. */
  src: string | null;
  host: string | null;
  firstParty: boolean;
  inline: boolean;
  inlineLength: number;
  patterns: ScriptPatternHit[];
}

export interface SensitiveInputHandler {
  kind: SensitiveFieldKind;
  handler: string;
}

export interface ScriptAnalysis {
  available: boolean;
  externalScriptCount: number;
  inlineScriptCount: number;
  thirdPartyScriptHosts: string[];
  inlinePatternHits: { id: ScriptPatternId; label: string; count: number; confidence: Confidence }[];
  sensitiveInputHandlers: SensitiveInputHandler[];
  clipboardIndicators: number;
  keyboardIndicators: number;
  suspiciousOverlay: boolean;
  suspiciousOverlayEvidence: string[];
  risk: "none" | "low" | "medium" | "high";
  confidence: Confidence;
  findings: SecurityFinding[];
  limitations: string[];
}

/* -------------------------------------------------------------- evidence --- */

export interface ObservedResource {
  host: string;
  url: string;
  type: string;
  count: number;
  firstParty: boolean;
}

export interface PageEvidence {
  url: string;
  origin: string;
  title: string;
  isTopFrame: boolean;
  collectedAt: number;
  forms: FormMetadata[];
  scripts: ScriptMetadata[];
  resources: ObservedResource[];
  mixedContentCount: number;
  mixedContentExamples: string[];
  sensitiveInputCount: number;
  passwordFieldCount: number;
  sensitiveInputHandlers: SensitiveInputHandler[];
  clipboardHandlerIndicators: string[];
  suspiciousOverlay: boolean;
  suspiciousOverlayEvidence: string[];
  iframeCount: number;
  hiddenIframeCount: number;
  hiddenIframeExamples: string[];
  brandMismatchDetected: boolean;
  brandMismatchBrand: string | null;
  brandMismatchEvidence: string[];
  limitations: string[];
}

/* --------------------------------------------------------------- cookies --- */

export type SameSiteValue = "no_restriction" | "lax" | "strict" | "unspecified";

export interface CookieSnapshot {
  name: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: SameSiteValue;
  session: boolean;
  expirationDate: number | null;
  hostOnly: boolean;
  storeId: string;
  firstParty: boolean | null;
}

export type CookiePurpose = "session" | "tracking" | "security-concern" | "functional" | "unknown";

export interface CookieAnalysis {
  key: string;
  name: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: SameSiteValue;
  session: boolean;
  expirationDate: number | null;
  firstParty: boolean | null;
  purposes: CookiePurpose[];
  confidence: Confidence;
  concerns: string[];
  notes: string[];
  deletable: boolean;
}

export interface CookieReport {
  available: boolean;
  reason: string | null;
  total: number;
  firstPartyCount: number;
  thirdPartyCount: number;
  sessionCount: number;
  trackingCount: number;
  concernCount: number;
  cookies: CookieAnalysis[];
  findings: SecurityFinding[];
  limitations: string[];
  deletedThisSession: number;
}

/* -------------------------------------------------------------- trackers --- */

export type TrackerCategory =
  | "analytics"
  | "advertising"
  | "social"
  | "session_replay"
  | "fingerprinting";

export interface TrackerDefinition {
  domain: string;
  company: string;
  category: TrackerCategory;
  confidence: Confidence;
  source: string;
}

export interface TrackerObservation {
  domain: string;
  company: string | null;
  category: TrackerCategory | "unknown";
  confidence: Confidence | null;
  source: string | null;
  requests: number;
  resourceTypes: string[];
  recognized: boolean;
  blocked: boolean | null;
}

export interface TrackerReport {
  available: boolean;
  reason: string | null;
  observedThirdPartyDomains: number;
  recognizedCount: number;
  unknownCount: number;
  thirdPartyRequestCount: number;
  trackers: TrackerObservation[];
  unknownDomains: { domain: string; requests: number; resourceTypes: string[] }[];
  blockedRecent: number | null;
  blockedNote: string | null;
  findings: SecurityFinding[];
  limitations: string[];
}

/* ------------------------------------------------------------- reputation --- */

export interface ReputationMatch {
  domain: string;
  label: string;
  severity: "critical" | "high";
  source: string;
  providerId: string;
  fetchedAt: number;
}

export interface ReputationResult {
  matches: ReputationMatch[];
  providerId: string;
  available: boolean;
  reason: string | null;
  cached: boolean;
}

/* --------------------------------------------------------------- phishing --- */

export type PhishingVerdict = "none" | "weak" | "suspicious" | "likely" | "confirmed";

export interface PhishingSignals {
  verdict: PhishingVerdict;
  riskScore: number;
  brandImpersonation: BrandImpersonation[];
  indicators: string[];
  credentialCollection: boolean;
  deceptiveContext: boolean;
  knownReputationMatch: ReputationMatch | null;
  explanation: string;
}

/* --------------------------------------------------------------- privacy --- */

export type ProtectionMode = "off" | "standard" | "strict" | "custom";

export interface BlockCategories {
  analytics: boolean;
  advertising: boolean;
  social: boolean;
  session_replay: boolean;
  fingerprinting: boolean;
}

export interface Settings {
  version: number;
  protectionMode: ProtectionMode;
  blockCategories: BlockCategories;
  strictExtra: boolean;
  cookieToolsEnabled: boolean;
  sensitiveFormWarnings: boolean;
  suspiciousScriptAlerts: boolean;
  autoScan: boolean;
  showLowConfidenceFindings: boolean;
  allowlist: string[];
}

export interface HistoryEntry {
  domain: string;
  score: number | null;
  classification: Classification;
  critical: boolean;
  findingCounts: Partial<Record<FindingCategory, number>>;
  assessedAt: number;
}

export interface PermissionState {
  cookies: boolean;
  hostAccess: boolean;
  contentScript: boolean;
  dnrFeedback: boolean;
  message: string | null;
}

export interface ProtectionStatus {
  enabledRulesets: string[];
  dynamicAllowRules: number;
  mode: ProtectionMode;
  blockingActive: boolean;
  allowlisted: boolean;
  lastSyncedAt: number | null;
  error: string | null;
}

/* ------------------------------------------------------------- headers --- */

export interface SecurityHeaderItem {
  name: string;
  label: string;
  value: string | null;
  present: boolean;
  critical: boolean;
  explanation: string;
}

export interface SecurityHeadersReport {
  available: boolean;
  headers: SecurityHeaderItem[];
  presentCount: number;
  missingCount: number;
  score: number;
  findings: SecurityFinding[];
  limitations: string[];
  error: string | null;
}

/* -------------------------------------------------------- domain intel --- */

export interface DomainIntelReport {
  available: boolean;
  domain: string;
  domainAgeDays: number | null;
  registrationDate: string | null;
  expiryDate: string | null;
  registrar: string | null;
  ctCertAgeDays: number | null;
  ctCertTotal: number | null;
  ctIssuers: string[];
  hasSpf: boolean;
  hasDmarc: boolean;
  dmarcPolicy: string | null;
  mxRecords: string[];
  aRecords: string[];
  findings: SecurityFinding[];
  limitations: string[];
  error: string | null;
}

export interface TabSnapshot {
  tabId: number;
  url: string;
  domain: string;
  title: string;
  fetchedAt: number;
  assessment: TrustAssessment;
  connection: ConnectionInfo;
  forms: FormAnalysis[];
  scripts: ScriptAnalysis;
  cookies: CookieReport;
  trackers: TrackerReport;
  protection: ProtectionStatus;
  permissions: PermissionState;
  allowlisted: boolean;
  evidence: PageEvidence | null;
  pageEvidenceAvailable: boolean;
  headers?: SecurityHeadersReport;
  domainIntel?: DomainIntelReport;
}

/* ---------------------------------------------------------------- history --- */

export interface StoredSnapshotMeta {
  snapshot: TabSnapshot;
  savedAt: number;
}

export interface SubmissionRiskInput {
  pageUrl: string;
  formIndex: number;
  action: string | null;
  actionHost: string | null;
  actionChanged: boolean;
  method: string;
  fieldKinds: SensitiveFieldKind[];
  hasPassword: boolean;
  hasOtp: boolean;
  hasCard: boolean;
}

export interface SubmissionDecision {
  decision: "allow" | "warn";
  title: string;
  summary: string;
  reasons: string[];
  risk: "none" | "low" | "medium" | "high" | "critical";
  assessment: TrustAssessment | null;
  allowlisted: boolean;
}
