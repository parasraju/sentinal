import { HISTORY_KEY, HISTORY_LIMIT } from "../shared/constants";
import type { FindingCategory, HistoryEntry, TrustAssessment } from "../shared/types";
import { sanitizeHistory } from "../shared/validation";

function findingCounts(assessment: TrustAssessment): Partial<Record<FindingCategory, number>> {
  const counts: Partial<Record<FindingCategory, number>> = {};
  for (const finding of assessment.findings) {
    if (finding.penalty <= 0) continue;
    counts[finding.category] = (counts[finding.category] ?? 0) + 1;
  }
  return counts;
}

export async function getHistory(): Promise<HistoryEntry[]> {
  const stored = await chrome.storage.local.get(HISTORY_KEY);
  return sanitizeHistory(stored[HISTORY_KEY]) as HistoryEntry[];
}

export async function recordAssessment(assessment: TrustAssessment, now = Date.now()): Promise<void> {
  if (!assessment.domain || assessment.domain === "unknown") return;
  const history = await getHistory();
  const entry: HistoryEntry = {
    domain: assessment.domain,
    score: assessment.score,
    classification: assessment.classification,
    critical: assessment.critical,
    findingCounts: findingCounts(assessment),
    assessedAt: assessment.assessedAt || now,
  };
  const recentIndex = history.findIndex(
    (item) => item.domain === entry.domain && Math.abs(item.assessedAt - entry.assessedAt) < 10 * 60 * 1000,
  );
  if (recentIndex >= 0) history.splice(recentIndex, 1);
  history.unshift(entry);
  await chrome.storage.local.set({ [HISTORY_KEY]: history.slice(0, HISTORY_LIMIT) });
}

export async function clearHistory(): Promise<void> {
  await chrome.storage.local.remove(HISTORY_KEY);
}
