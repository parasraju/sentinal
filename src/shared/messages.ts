import type {
  HistoryEntry,
  PageEvidence,
  Settings,
  SubmissionDecision,
  SubmissionRiskInput,
  TabSnapshot,
  TrustAssessment,
} from "./types";

export interface PublicSettings {
  sensitiveFormWarnings: boolean;
  suspiciousScriptAlerts: boolean;
  suspiciousScriptAlertsLabel: string;
  allowlisted: boolean;
}

export interface SnapshotResponse {
  ok: boolean;
  snapshot: TabSnapshot | null;
  error: string | null;
}

export interface SimpleResponse {
  ok: boolean;
  error: string | null;
}

export interface SettingsResponse {
  ok: boolean;
  settings: Settings | null;
  error: string | null;
}

export interface HistoryResponse {
  ok: boolean;
  history: HistoryEntry[];
  error: string | null;
}

export interface DeleteCookieItem {
  name: string;
  domain: string;
  path: string;
  storeId: string;
}

export interface DeleteCookiesResponse {
  ok: boolean;
  deleted: number;
  failed: number;
  errors: string[];
  deletedThisSession: number;
}

export type ExtensionMessage =
  | { type: "CONTENT_READY"; url: string }
  | { type: "PAGE_EVIDENCE"; evidence: PageEvidence }
  | { type: "GET_SNAPSHOT"; tabId?: number; force?: boolean }
  | { type: "RESCAN"; tabId?: number }
  | { type: "CHECK_SUBMISSION"; input: SubmissionRiskInput }
  | { type: "GET_SETTINGS" }
  | { type: "UPDATE_SETTINGS"; settings: Settings }
  | { type: "DELETE_COOKIE"; tabId: number; cookie: DeleteCookieItem }
  | { type: "DELETE_COOKIES"; tabId: number; cookies: DeleteCookieItem[] }
  | { type: "GET_HISTORY" }
  | { type: "CLEAR_HISTORY" }
  | { type: "CLEAR_ALL_DATA" }
  | { type: "SET_ALLOWLIST"; domain: string; allowlisted: boolean }
  | { type: "GET_PROTECTION_STATUS" }
  | { type: "OPEN_OPTIONS" };

export type ContentReadyResponse = {
  ok: boolean;
  publicSettings: PublicSettings | null;
};

export type PageEvidenceResponse = {
  ok: boolean;
  assessment: TrustAssessment | null;
  allowlisted: boolean;
};

export type SubmissionResponse = {
  ok: boolean;
  decision: SubmissionDecision | null;
  error: string | null;
};

export type DeleteCookieResponse = SimpleResponse & { deleted: number; failed: number; deletedThisSession: number };

/** Broadcast from the service worker to open extension pages and the content script. */
export interface SnapshotUpdatedMessage {
  type: "SNAPSHOT_UPDATED";
  tabId: number;
  assessment: TrustAssessment;
  allowlisted: boolean;
}
