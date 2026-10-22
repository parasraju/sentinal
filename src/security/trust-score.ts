import { findBadHosts } from "./reputation";
import { ASSESSMENT_VERSION, CATEGORY_CAPS, FINDING_LIMIT, PENALTIES } from "../shared/constants";
import type {
  ConnectionInfo,
  CookieReport,
  DomainIntelReport,
  FormAnalysis,
  PageEvidence,
  PhishingSignals,
  ReputationResult,
  ScriptAnalysis,
  SecurityFinding,
  SecurityHeadersReport,
  TrackerReport,
  TrustAssessment,
  UrlSignals,
} from "../shared/types";
import {
  classificationForScore,
  clampScore,
  compareFindings,
  isCriticalFinding,
  maxConfidence,
  maxSeverity,
} from "./risk-classifier";

export interface TrustAssessmentInput {
  url: string;
  signals: UrlSignals;
  connection: ConnectionInfo;
  phishing: PhishingSignals;
  page: PageEvidence | null;
  forms: FormAnalysis[];
  scripts: ScriptAnalysis;
  cookies: CookieReport;
  trackers: TrackerReport;
  reputation: ReputationResult;
  headers?: SecurityHeadersReport;
  domainIntel?: DomainIntelReport;
  now?: number;
}

function dedupeFindings(findings: SecurityFinding[]): SecurityFinding[] {
  const merged = new Map<string, SecurityFinding>();
  for (const finding of findings) {
    const existing = merged.get(finding.id);
    if (!existing) {
      merged.set(finding.id, {
        ...finding,
        evidence: Array.from(new Set(finding.evidence)).slice(0, 12),
      });
      continue;
    }
    merged.set(finding.id, {
      ...existing,
      severity: maxSeverity(existing.severity, finding.severity),
      confidence: maxConfidence(existing.confidence, finding.confidence),
      penalty: Math.max(existing.penalty, finding.penalty),
      evidence: Array.from(new Set([...existing.evidence, ...finding.evidence])).slice(0, 12),
      explanation:
        finding.penalty > existing.penalty ? finding.explanation : existing.explanation,
    });
  }
  return Array.from(merged.values());
}

function formFindings(forms: FormAnalysis[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const externalSensitive = forms.filter((form) => form.flags.includes("external-sensitive"));
  const externalAccount = forms.filter((form) => form.flags.includes("external-account"));
  const insecure = forms.filter((form) => form.flags.includes("insecure-action"));
  const changed = forms.filter((form) => form.flags.includes("action-changed"));
  const getSensitive = forms.filter((form) => form.flags.includes("get-sensitive"));
  const jsActions = forms.filter((form) => form.flags.includes("action-javascript"));
  const trusted = forms.filter((form) => form.flags.includes("trusted-provider"));

  const describe = (form: FormAnalysis): string =>
    `${form.destinationHost ?? "unknown destination"}${form.sensitiveKinds.length ? ` — ${form.sensitiveKinds.join(", ")}` : ""}`;

  if (externalSensitive.length > 0) {
    findings.push({
      id: "form:external-sensitive",
      category: "form",
      severity: "high",
      confidence: "high",
      title: "Sensitive form submits to an unrelated external origin",
      explanation: `${externalSensitive.length} form${externalSensitive.length === 1 ? "" : "s"} with password, one-time-code, card, or identity fields submit${externalSensitive.length === 1 ? "s" : ""} to an origin unrelated to this page and not on Sentinel's known provider list. The final recipient cannot be confirmed from the page alone.`,
      evidence: externalSensitive.slice(0, 6).map(describe),
      remediation:
        "Do not enter credentials or payment data. Verify the destination through the organization's independently obtained official address.",
      source: "observed",
      penalty: PENALTIES.sensitiveFormExternal,
    });
  }

  if (externalAccount.length > 0) {
    findings.push({
      id: "form:external-account",
      category: "form",
      severity: "medium",
      confidence: "medium",
      title: "Account form submits to an external origin",
      explanation: `${externalAccount.length} form${externalAccount.length === 1 ? "" : "s"} with account or contact fields submit to a different origin. This is sometimes legitimate but requires verification.`,
      evidence: externalAccount.slice(0, 6).map(describe),
      remediation: "Confirm the destination host before submitting account information.",
      source: "observed",
      penalty: PENALTIES.riskyFormDestination,
    });
  }

  if (insecure.length > 0) {
    findings.push({
      id: "form:insecure-action",
      category: "form",
      severity: "high",
      confidence: "high",
      title: "Form sends data over unencrypted HTTP",
      explanation:
        "One or more forms on this HTTPS page submit to an HTTP destination. Data could be exposed or altered in transit.",
      evidence: insecure.slice(0, 6).map(describe),
      remediation: "Do not submit sensitive data to an unencrypted form.",
      source: "observed",
      penalty: PENALTIES.insecureFormAction,
    });
  }

  if (changed.length > 0) {
    findings.push({
      id: "form:action-changed",
      category: "form",
      severity: "medium",
      confidence: "medium",
      title: "Form destination changed after page load",
      explanation:
        "A form's action attribute changed while the page was open. This can be legitimate in single-page applications, but it obscures where data will be sent.",
      evidence: changed.slice(0, 6).map(describe),
      remediation: "Avoid submitting sensitive information until the destination can be verified.",
      source: "observed",
      penalty: PENALTIES.dynamicFormAction,
    });
  }

  if (getSensitive.length > 0) {
    findings.push({
      id: "form:sensitive-get",
      category: "form",
      severity: "medium",
      confidence: "high",
      title: "Sensitive form uses GET",
      explanation:
        "A form with sensitive fields uses GET. Browsers may place submitted values in the URL, exposing them to history, logs, or referrer leakage.",
      evidence: getSensitive.slice(0, 6).map(describe),
      remediation: "Do not submit passwords or payment data through a GET form.",
      source: "observed",
      penalty: 15,
    });
  }

  if (jsActions.length > 0) {
    findings.push({
      id: "form:javascript-action",
      category: "form",
      severity: "high",
      confidence: "medium",
      title: "Form uses a javascript: destination",
      explanation:
        "A form action begins with javascript:, which hides the real submission path. The actual recipient is unobservable.",
      evidence: jsActions.slice(0, 6).map(describe),
      remediation: "Do not enter sensitive information into this form.",
      source: "observed",
      penalty: 20,
    });
  }

  if (trusted.length > 0) {
    findings.push({
      id: "form:trusted-provider",
      category: "form",
      severity: "info",
      confidence: "high",
      title: "Form uses a common identity or payment provider",
      explanation:
        "One or more forms submit to a well-known identity or payment provider. This is not proof of safety; confirm that this page is expected to use that provider.",
      evidence: Array.from(
        new Set(trusted.map((form) => `${form.trustedProvider ?? "provider"} — ${form.destinationHost ?? "unknown"}`)),
      ).slice(0, 6),
      remediation: "Confirm the provider name and the page's identity before continuing.",
      source: "observed",
      penalty: 0,
    });
  }

  return findings;
}

function phishingFindings(
  phishing: PhishingSignals,
  reputation: ReputationResult,
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const confirmed = phishing.knownReputationMatch ?? reputation.matches[0] ?? null;

  if (confirmed) {
    findings.push({
      id: "reputation:known-phishing",
      category: "reputation",
      severity: "critical",
      confidence: "high",
      title: "Domain matches a known-bad local list",
      explanation: `The page domain matches “${confirmed.label}” in Sentinel's bundled local reputation list (${confirmed.providerId}). No URL, page content, or browsing data was sent anywhere.`,
      evidence: [`Matched domain: ${confirmed.domain}`, `Provider: ${confirmed.providerId}`],
      remediation:
        "Leave this page. Do not enter credentials, payment data, or one-time codes. Reach the organization through an independently obtained address.",
      source: confirmed.providerId.startsWith("sentinel") ? "local-list" : "reputation-feed",
      penalty: PENALTIES.confirmedPhishing,
    });
  }

  if (phishing.brandImpersonation.length > 0) {
    findings.push({
      id: "domain:brand-impersonation",
      category: "domain",
      severity: "medium",
      confidence: "medium",
      title: "Domain resembles a trusted brand",
      explanation: phishing.brandImpersonation
        .slice(0, 2)
        .map((item) => item.explanation)
        .join(" "),
      evidence: phishing.brandImpersonation
        .slice(0, 4)
        .map((item) => `${item.brandName} → ${item.observedDomain} (${item.method})`),
      remediation:
        "Do not assume brand ownership from the name. Navigate to the brand's official website through an independent source.",
      source: "local-heuristic",
      penalty: PENALTIES.unusualImpersonation,
    });
  }

  if (phishing.verdict === "likely" && !confirmed) {
    findings.push({
      id: "phishing:supported-impersonation",
      category: "phishing",
      severity: "high",
      confidence: "high",
      title: "Multiple phishing indicators support impersonation",
      explanation:
        "The URL combines brand-impersonation, login, or encoding indicators that are uncommon on legitimate login pages. This is a heuristic assessment, not a confirmed detection.",
      evidence: phishing.indicators.slice(0, 8),
      remediation:
        "Do not enter credentials. Close the page and navigate to the service through a known-good bookmark or official app.",
      source: "local-heuristic",
      penalty: PENALTIES.supportedImpersonation,
    });
  } else if (phishing.verdict === "suspicious" && !confirmed) {
    findings.push({
      id: "phishing:suspicious-impersonation",
      category: "phishing",
      severity: "medium",
      confidence: "medium",
      title: "Suspicious impersonation indicators",
      explanation:
        "The URL contains indicators that are sometimes associated with phishing. They can also appear on legitimate sites, so they are not proof of malicious intent.",
      evidence: phishing.indicators.slice(0, 8),
      remediation: "Check the domain carefully and avoid entering sensitive information until verified.",
      source: "local-heuristic",
      penalty: 25,
    });
  } else if (phishing.verdict === "weak" && !confirmed) {
    findings.push({
      id: "phishing:weak-indicators",
      category: "phishing",
      severity: "info",
      confidence: "low",
      title: "Weak URL indicators observed",
      explanation:
        "The URL contains a small number of indicators that are common on both legitimate and malicious sites. No penalty was applied.",
      evidence: phishing.indicators.slice(0, 6),
      remediation: "No action required unless other warnings are present.",
      source: "local-heuristic",
      penalty: 0,
    });
  }

  if (
    phishing.credentialCollection &&
    (phishing.verdict === "likely" ||
      phishing.verdict === "suspicious" ||
      phishing.verdict === "confirmed")
  ) {
    findings.push({
      id: "phishing:credential-collection",
      category: "phishing",
      severity: phishing.deceptiveContext ? "high" : "medium",
      confidence: phishing.deceptiveContext ? "high" : "medium",
      title: "Credential collection on a deceptive page",
      explanation:
        "The page collects credentials or payment data while its domain shows impersonation-related indicators. This combination is consistent with credential theft, but intent cannot be proven from observable evidence alone.",
      evidence: [
        "Credential or payment fields were present in the page metadata.",
        ...phishing.indicators.filter((indicator) => indicator.includes("brand") || indicator.includes("punycode") || indicator.includes("login")),
      ].slice(0, 8),
      remediation:
        "Do not submit this form. Leave the page and access the service through an official, independently obtained address.",
      source: "local-heuristic",
      penalty: PENALTIES.deceptiveCredentialCollection,
    });
  }

  return findings;
}

function badHostFindings(input: TrustAssessmentInput, confirmedReputation: boolean): SecurityFinding[] {
  if (!input.page) return [];
  const hosts = new Set<string>();
  for (const script of input.page.scripts) if (script.host) hosts.add(script.host);
  for (const resource of input.page.resources) hosts.add(resource.host);
  for (const form of input.page.forms) if (form.actionHost) hosts.add(form.actionHost);
  const pageHost = input.signals.hostname;
  if (pageHost) hosts.delete(pageHost);

  let matches = findBadHosts(Array.from(hosts), input.now ?? Date.now());
  if (confirmedReputation) {
    const knownDomain = input.phishing.knownReputationMatch?.domain;
    if (knownDomain) matches = matches.filter((match) => match.domain !== knownDomain);
  }
  if (matches.length === 0) return [];

  return [
    {
      id: "reputation:known-bad-host",
      category: "reputation",
      severity: "critical",
      confidence: "high",
      title: "Known-bad host contacted by this page",
      explanation:
        "A script host or network destination matches Sentinel's bundled local bad-domain list. This list is a demonstration and is not a live threat feed; treat the finding as a strong reason to avoid the page pending verification.",
      evidence: matches.slice(0, 6).map((match) => `${match.domain} — ${match.label}`),
      remediation:
        "Leave the page. Do not enter credentials. Report the site to the relevant brand or hosting provider if it impersonates a service.",
      source: "local-list",
      penalty: PENALTIES.knownMalicious,
    },
  ];
}

function urlHeuristicFindings(signals: UrlSignals): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  if (signals.hasAtSymbol) {
    findings.push({
      id: "url:at-symbol",
      category: "phishing",
      severity: "high",
      confidence: "high",
      title: "URL contains '@' credential confusion token",
      explanation:
        "The URL includes an '@' symbol in the authority component. Phishing sites frequently use this syntax to hide the actual host behind fake brand names.",
      evidence: [signals.normalizedUrl ?? signals.input],
      remediation: "Verify the actual destination domain before clicking or entering data.",
      source: "local-heuristic",
      penalty: PENALTIES.atSymbolInUrl,
    });
  }

  if (signals.hasDoubleSlashRedirect) {
    findings.push({
      id: "url:double-slash-redirect",
      category: "phishing",
      severity: "medium",
      confidence: "medium",
      title: "Deceptive path redirect syntax ('//')",
      explanation:
        "The URL path contains double slashes ('//') after the root slash. This technique is often used in open-redirect and protocol-relative phishing tricks.",
      evidence: [signals.normalizedUrl ?? signals.input],
      remediation: "Verify the domain in the address bar carefully.",
      source: "local-heuristic",
      penalty: PENALTIES.doubleSlashRedirect,
    });
  }

  if (signals.hasNonStandardPort) {
    findings.push({
      id: "url:non-standard-port",
      category: "connection",
      severity: "medium",
      confidence: "medium",
      title: "Unusual network port specified in URL",
      explanation:
        "The website is served on a non-standard port rather than port 80 (HTTP) or 443 (HTTPS). This can indicate an unmanaged server or phishing host.",
      evidence: [signals.normalizedUrl ?? signals.input],
      remediation: "Confirm why this service requires an unusual port number.",
      source: "observed",
      penalty: PENALTIES.nonStandardPort,
    });
  }

  if (signals.hasHttpsInHostname) {
    findings.push({
      id: "url:https-in-hostname",
      category: "domain",
      severity: "high",
      confidence: "high",
      title: "Deceptive 'https' token in domain name",
      explanation:
        "The domain name itself contains 'https-', 'https.', or '-https' to mislead users into believing a secure protocol is part of the organization's name.",
      evidence: [signals.hostname ?? ""],
      remediation: "Look at the real registrable domain rather than the prefix.",
      source: "local-heuristic",
      penalty: PENALTIES.httpsTokenInDomain,
    });
  }

  return findings;
}

function pageDomFindings(page: PageEvidence | null): SecurityFinding[] {
  if (!page) return [];
  const findings: SecurityFinding[] = [];

  if (page.hiddenIframeCount > 0) {
    findings.push({
      id: "content:hidden-iframe",
      category: "content",
      severity: "medium",
      confidence: "medium",
      title: "Hidden or miniature iframe detected",
      explanation: `${page.hiddenIframeCount} hidden or zero-dimension iframe${page.hiddenIframeCount === 1 ? " was" : "s were"} found in the DOM. Deceptive sites often use hidden iframes for clickjacking, credential harvesting, or silent redirection.`,
      evidence: page.hiddenIframeExamples.slice(0, 6),
      remediation: "Ensure you are interacting with genuine page elements and not overlayed or embedded frames.",
      source: "observed",
      penalty: PENALTIES.hiddenIframe,
    });
  }

  if (page.brandMismatchDetected) {
    findings.push({
      id: "phishing:brand-mismatch-login",
      category: "phishing",
      severity: "high",
      confidence: "high",
      title: `Brand mismatch on login page (${page.brandMismatchBrand ?? "recognized brand"})`,
      explanation: `The page prominently displays ${page.brandMismatchBrand ?? "a major brand"} branding and contains password or credential fields, but the current domain does not belong to that organization. This is a classic hallmark of credential harvesting.`,
      evidence: page.brandMismatchEvidence.slice(0, 8),
      remediation: "Do not enter your credentials. Immediately navigate to the brand's verified website through a known bookmark or direct entry.",
      source: "observed",
      penalty: PENALTIES.brandMismatchFakeLogin,
    });
  }

  return findings;
}

function calculateCappedDeductions(findings: SecurityFinding[]): number {
  const bucketSums: Record<"transport" | "domain" | "phishing" | "content" | "reputation", number> = {
    transport: 0,
    domain: 0,
    phishing: 0,
    content: 0,
    reputation: 0,
  };

  for (const finding of findings) {
    const penalty = Math.max(0, finding.penalty);
    if (penalty === 0) continue;

    switch (finding.category) {
      case "connection":
      case "header":
        bucketSums.transport += penalty;
        break;
      case "domain":
      case "dns":
        bucketSums.domain += penalty;
        break;
      case "phishing":
      case "form":
        bucketSums.phishing += penalty;
        break;
      case "content":
      case "script":
      case "cookie":
      case "tracker":
      case "permission":
        bucketSums.content += penalty;
        break;
      case "reputation":
        bucketSums.reputation += penalty;
        break;
    }
  }

  const cappedTransport = Math.min(bucketSums.transport, CATEGORY_CAPS.transport);
  const cappedDomain = Math.min(bucketSums.domain, CATEGORY_CAPS.domain);
  const cappedPhishing = Math.min(bucketSums.phishing, CATEGORY_CAPS.phishing);
  const cappedContent = Math.min(bucketSums.content, CATEGORY_CAPS.content);
  const cappedReputation = Math.min(bucketSums.reputation, CATEGORY_CAPS.reputation);

  return cappedTransport + cappedDomain + cappedPhishing + cappedContent + cappedReputation;
}

export function assessWebsite(input: TrustAssessmentInput): TrustAssessment {
  const now = input.now ?? Date.now();
  const findings: SecurityFinding[] = [];
  const limitations: string[] = [];

  const urlAnalyzable =
    input.signals.normalizedUrl !== null &&
    (input.signals.protocol === "http:" || input.signals.protocol === "https:");
  const hasPage = input.page !== null;
  const evidenceCompleteness =
    hasPage && input.cookies.available && input.trackers.available
      ? "full"
      : hasPage || input.cookies.available || input.trackers.available
        ? "partial"
        : "url-only";

  findings.push(...phishingFindings(input.phishing, input.reputation));
  const confirmedReputation = Boolean(input.phishing.knownReputationMatch ?? input.reputation.matches[0]);
  findings.push(...badHostFindings(input, confirmedReputation));
  findings.push(...urlHeuristicFindings(input.signals));
  findings.push(...pageDomFindings(input.page));
  findings.push(...formFindings(input.forms));
  findings.push(...input.scripts.findings);
  findings.push(...input.cookies.findings);
  findings.push(...input.trackers.findings);
  if (input.headers?.findings) {
    findings.push(...input.headers.findings);
  }
  if (input.domainIntel?.findings) {
    findings.push(...input.domainIntel.findings);
  }

  if (!urlAnalyzable) {
    findings.push({
      id: "permission:unsupported-url",
      category: "permission",
      severity: "info",
      confidence: "high",
      title: "This page cannot be assessed",
      explanation:
        "Sentinel only assesses http:// and https:// pages. Browser-internal pages, extension pages, and local files are not inspected.",
      evidence: ["The tab URL is not an assessable web address."],
      remediation: "Open a regular website to use Sentinel.",
      source: "browser",
      penalty: 0,
    });
  } else {
    if (input.signals.protocol === "https:") {
      findings.push({
        id: "connection:https",
        category: "connection",
        severity: "info",
        confidence: "high",
        title: "HTTPS connection observed",
        explanation:
          "The browser loaded this page over HTTPS. Encryption protects data in transit but does not establish that the website owner is trustworthy.",
        evidence: [input.signals.normalizedUrl ?? input.url],
        remediation: "HTTPS is expected. Continue to evaluate the site's identity and behavior separately.",
        source: "browser",
        penalty: 0,
      });
    } else {
      findings.push({
        id: "connection:http",
        category: "connection",
        severity: "medium",
        confidence: "high",
        title: "Unencrypted HTTP connection",
        explanation:
          "This page uses HTTP. Data between the browser and the site can be read or changed by parties on the network. HTTP alone does not prove the site is malicious.",
        evidence: [input.signals.normalizedUrl ?? input.url],
        remediation:
          "Avoid entering passwords, payment data, or identity information. Prefer the site's HTTPS address if one exists.",
        source: "browser",
        penalty: PENALTIES.insecureHttp,
      });
    }

    if (input.connection.mixedContentCount > 0) {
      findings.push({
        id: "connection:mixed-content",
        category: "connection",
        severity: "medium",
        confidence: "medium",
        title: "Mixed content resources observed",
        explanation: `${input.connection.mixedContentCount} resource${
          input.connection.mixedContentCount === 1 ? "" : "s"
        } load over HTTP on an HTTPS page. Those resources are not protected by the page's encryption.`,
        evidence: input.connection.mixedContentExamples.slice(0, 6),
        remediation: "Treat data entered on this page with caution until the site fixes mixed content.",
        source: "observed",
        penalty: PENALTIES.mixedContent,
      });
    }

    if (input.signals.isShortener) {
      findings.push({
        id: "domain:url-shortener",
        category: "domain",
        severity: "info",
        confidence: "high",
        title: "URL shortener detected",
        explanation:
          "The address is a known URL shortener. The final destination is not visible before navigation and cannot be verified by Sentinel.",
        evidence: [input.signals.hostname ?? ""],
        remediation: "Expand the link independently and verify the final domain before entering information.",
        source: "local-list",
        penalty: 0,
      });
    }

    if (input.signals.isIpAddress) {
      findings.push({
        id: "domain:ip-host",
        category: "domain",
        severity: "info",
        confidence: "medium",
        title: "Website hosted on an IP address",
        explanation:
          "The site is addressed by a raw IP address. This is normal for some services and development tools, but it prevents domain-ownership checks.",
        evidence: [input.signals.hostname ?? ""],
        remediation: "Verify the owner independently if the page requests sensitive information.",
        source: "observed",
        penalty: 0,
      });
    }

    if (input.signals.hasSuspiciousTld) {
      findings.push({
        id: "domain:suspicious-tld",
        category: "domain",
        severity: "info",
        confidence: "low",
        title: "Uncommon top-level domain",
        explanation:
          "The top-level domain appears on Sentinel's list of frequently abused suffixes. Legitimate sites use these too; this is a weak indicator only.",
        evidence: [input.signals.publicSuffix ?? ""],
        remediation: "No action required unless other indicators or warnings are present.",
        source: "local-list",
        penalty: 0,
      });
    }
  }

  if (evidenceCompleteness !== "full") {
    const missing: string[] = [];
    if (!hasPage) missing.push("page form/script/request evidence");
    if (!input.cookies.available) missing.push("cookie metadata");
    if (!input.trackers.available) missing.push("third-party request evidence");
    findings.push({
      id: "permission:limited-evidence",
      category: "permission",
      severity: "info",
      confidence: "high",
      title: "Some evidence is unavailable",
      explanation: `Sentinel could not collect: ${missing.join(", ")}. Unavailable evidence is treated as unknown, never as safe.`,
      evidence: [
        input.cookies.reason,
        input.trackers.reason,
        ...(hasPage ? [] : ["The content script did not report page metadata."]),
      ].filter((item): item is string => Boolean(item)).slice(0, 6),
      remediation:
        "Reload the page. If the problem persists, check that Sentinel has site access on this domain.",
      source: "browser",
      penalty: 0,
    });
  }

  for (const form of input.forms) limitations.push(...form.limitations);
  limitations.push(...input.connection.limitations);
  limitations.push(...input.scripts.limitations);
  limitations.push(...input.cookies.limitations);
  limitations.push(...input.trackers.limitations);
  if (input.headers?.limitations) limitations.push(...input.headers.limitations);
  if (input.domainIntel?.limitations) limitations.push(...input.domainIntel.limitations);
  limitations.push(
    "The trust score is a deterministic estimate from observable evidence. A high score is not a guarantee that a website is safe.",
  );

  const deduped = dedupeFindings(findings).sort(compareFindings).slice(0, FINDING_LIMIT);
  const uniqueLimitations = Array.from(new Set(limitations.filter(Boolean))).slice(0, 14);
  const critical = deduped.some(isCriticalFinding) || input.phishing.verdict === "confirmed";

  let score: number | null = null;
  // A numeric score is only meaningful when the core page, cookie, and tracker
  // evidence is available. Partial evidence remains explicitly unknown rather
  // than allowing the untouched 100-point baseline to imply safety.
  if (urlAnalyzable && evidenceCompleteness === "full") {
    const totalPenalty = calculateCappedDeductions(deduped);
    score = clampScore(100 - totalPenalty);
    if (critical) score = Math.min(score, 39);
  }

  const classification = critical
    ? "dangerous"
    : urlAnalyzable && evidenceCompleteness === "full"
      ? classificationForScore(score)
      : "unknown";

  let confidenceScore = 0;
  if (urlAnalyzable) {
    confidenceScore += 0.2;
    if (hasPage) confidenceScore += 0.25;
    if (input.cookies.available || input.trackers.available) confidenceScore += 0.15;
    if (input.headers?.available) confidenceScore += 0.15;
    if (input.domainIntel?.available) confidenceScore += 0.25;
  }
  confidenceScore = Math.min(1.0, Math.round(confidenceScore * 100) / 100);

  let confidence: TrustAssessment["confidence"];
  if (critical) confidence = "high";
  else if (evidenceCompleteness === "url-only" || !urlAnalyzable) confidence = "low";
  else if (confidenceScore >= 0.75) confidence = "high";
  else if (confidenceScore >= 0.45) confidence = "medium";
  else confidence = "low";

  const penalized = deduped.filter((finding) => finding.penalty > 0);
  const topFactors = urlAnalyzable && evidenceCompleteness === "full"
    ? penalized.length > 0
      ? penalized.slice(0, 3).map((finding) => finding.title)
      : ["No material risk indicators were observed in the available evidence."]
    : evidenceCompleteness === "url-only"
      ? ["Page evidence is unavailable, so Sentinel cannot produce a reliable numeric score."]
      : ["Some page evidence is unavailable, so Sentinel cannot produce a reliable numeric score."];

  return {
    domain: input.signals.registrableDomain ?? input.signals.hostname ?? "unknown",
    score,
    classification,
    confidence,
    confidenceScore,
    findings: deduped,
    assessedAt: now,
    assessmentVersion: ASSESSMENT_VERSION,
    critical,
    topFactors,
    limitations: uniqueLimitations,
    evidenceCompleteness,
  };
}
