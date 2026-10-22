import { observeBrowserTls } from "./certificate-checker";
import type { ConnectionInfo, PageEvidence } from "../shared/types";

export function analyzeConnection(
  url: string,
  evidence: PageEvidence | null,
  pageLoaded = true,
): ConnectionInfo {
  let protocol: ConnectionInfo["protocol"] = "other";
  try {
    const parsed = new URL(url);
    protocol =
      parsed.protocol === "https:" ? "https:" : parsed.protocol === "http:" ? "http:" : "other";
  } catch {
    protocol = "other";
  }

  const tls = observeBrowserTls(protocol, pageLoaded);
  const mixedContentCount = evidence?.mixedContentCount ?? 0;
  const mixedContentExamples = evidence?.mixedContentExamples ?? [];

  let status: ConnectionInfo["status"] = "unavailable";
  if (tls.status === "browser-https") status = "secure";
  else if (tls.status === "browser-http") status = "insecure";

  const explanation =
    mixedContentCount > 0
      ? `${tls.summary} ${mixedContentCount} observable resource${
          mixedContentCount === 1 ? "" : "s"
        } load over HTTP, which weakens the page's transport security.`
      : tls.summary;

  return {
    protocol,
    status,
    secure: status === "secure",
    mixedContentCount,
    mixedContentExamples,
    explanation,
    limitations: [
      ...tls.limitations,
      ...(evidence
        ? ["Mixed content is detected only from URLs visible in the DOM and Resource Timing API."]
        : ["Page-level mixed content could not be observed because page evidence is unavailable."]),
      "Transport security is reported separately from website reputation and never cancels phishing evidence.",
    ],
  };
}
