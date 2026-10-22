import type {
  PageEvidence,
  PhishingSignals,
  PhishingVerdict,
  ReputationMatch,
  UrlSignals,
} from "../shared/types";

const BRAND_WEIGHTS: Record<string, number> = {
  punycode: 35,
  lookalike: 35,
  token: 28,
  subdomain: 16,
};

function verdictFor(score: number, confirmed: boolean): PhishingVerdict {
  if (confirmed) return "confirmed";
  if (score >= 55) return "likely";
  if (score >= 30) return "suspicious";
  if (score >= 14) return "weak";
  return "none";
}

/**
 * Deterministic phishing heuristics. This function never fetches, executes, or
 * scores only by "unfamiliar domain": every point maps to an observable signal.
 */
export function detectPhishing(
  signals: UrlSignals,
  evidence: PageEvidence | null,
  reputation: ReputationMatch[] = [],
): PhishingSignals {
  const indicators = new Set<string>(signals.indicators);
  const known = reputation.find((match) => match.severity === "critical") ?? reputation[0] ?? null;
  let riskScore = 0;

  if (known) {
    riskScore = 100;
  }

  let bestBrandWeight = 0;
  for (const impersonation of signals.brandImpersonation) {
    bestBrandWeight = Math.max(bestBrandWeight, BRAND_WEIGHTS[impersonation.method] ?? 0);
  }
  if (bestBrandWeight > 0) {
    riskScore += bestBrandWeight;
    if (signals.hasLoginTerm) riskScore += 8;
    indicators.add("brand-impersonation");
  }

  if (signals.isPunycode) riskScore += 12;
  if (signals.hasMixedScripts) riskScore += 18;
  if (signals.hasEmbeddedCredentials) riskScore += 20;
  if (signals.isShortener) riskScore += 10;
  if (signals.isIpAddress) riskScore += 8;
  if (signals.hasSuspiciousTld) riskScore += 6;
  if (signals.hasLoginTerm) {
    riskScore += signals.loginTerms.some((term) => signals.hostname?.includes(term))
      ? 6
      : 3;
  }
  if (signals.urlLength > 120) riskScore += 2;
  if (signals.labelCount > 4) riskScore += 4;
  if (signals.usesEncoding) riskScore += 3;
  if (signals.suspiciousFileExtension) riskScore += 3;

  if (signals.hasAtSymbol) {
    riskScore += 20;
    indicators.add("at-symbol-in-url");
  }
  if (signals.hasDoubleSlashRedirect) {
    riskScore += 15;
    indicators.add("double-slash-redirect");
  }
  if (signals.hasNonStandardPort) {
    riskScore += 18;
    indicators.add("non-standard-port");
  }
  if (signals.hasHttpsInHostname) {
    riskScore += 25;
    indicators.add("https-token-in-domain");
  }
  if (evidence?.hiddenIframeCount && evidence.hiddenIframeCount > 0) {
    riskScore += 12;
    indicators.add("hidden-iframes");
  }
  if (evidence?.brandMismatchDetected) {
    riskScore += 35;
    indicators.add("fake-login-brand-mismatch");
  }

  const credentialCollection = Boolean(
    evidence &&
      (evidence.passwordFieldCount > 0 ||
        evidence.forms.some(
          (form) => form.hasPassword || form.hasOtp || form.hasCard || form.hasNationalId,
        )),
  );

  const hasDomainDeception =
    signals.brandImpersonation.length > 0 ||
    signals.isPunycode ||
    signals.hasMixedScripts ||
    signals.hasSuspiciousTld ||
    signals.hasHttpsInHostname ||
    Boolean(evidence?.brandMismatchDetected) ||
    (signals.isIpAddress && credentialCollection);

  if (credentialCollection && hasDomainDeception) {
    riskScore += 20;
    indicators.add("credential-collection-on-deceptive-domain");
  }

  if (
    credentialCollection &&
    evidence?.suspiciousOverlay &&
    signals.hasLoginTerm
  ) {
    riskScore += 6;
    indicators.add("credential-overlay");
  }

  const deceptiveContext =
    credentialCollection &&
    hasDomainDeception &&
    (signals.hasLoginTerm || signals.brandImpersonation.length > 0 || Boolean(evidence?.brandMismatchDetected));

  if (known) riskScore = Math.max(riskScore, 100);
  riskScore = known ? 100 : Math.min(99, Math.max(0, riskScore));
  const verdict = verdictFor(riskScore, Boolean(known));

  const explanation = (() => {
    if (known) {
      return `The domain matches a critical entry in Sentinel's bundled reputation list (${known.label}). This is a local list match, not a live threat-feed lookup.`;
    }
    if (evidence?.brandMismatchDetected) {
      return `The page displays branding for "${evidence.brandMismatchBrand}" on an unrelated domain ("${signals.hostname}"), which is a strong indicator of a spoofed login page.`;
    }
    if (signals.brandImpersonation.length > 0) {
      const first = signals.brandImpersonation[0];
      return `${first?.explanation ?? "The domain resembles a known brand."} ${
        credentialCollection
          ? "The page also contains fields that collect credentials or payment data."
          : "Verify the address through the brand's official website before continuing."
      }`;
    }
    if (signals.isPunycode || signals.hasMixedScripts) {
      return "The hostname uses encoded or mixed-script characters that can visually imitate another domain.";
    }
    if (signals.isShortener) {
      return "The address is a URL shortener. The final destination is not visible before navigation.";
    }
    if (signals.hasLoginTerm) {
      return "The address contains login-related terms. This alone is common and is not proof of phishing.";
    }
    return "No phishing-specific indicators were observed in the available URL and page evidence.";
  })();

  return {
    verdict,
    riskScore,
    brandImpersonation: signals.brandImpersonation,
    indicators: Array.from(indicators),
    credentialCollection,
    deceptiveContext,
    knownReputationMatch: known,
    explanation,
  };
}
