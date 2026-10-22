import { PENALTIES } from "../shared/constants";
import type {
  PageEvidence,
  ScriptAnalysis,
  ScriptMetadata,
  ScriptPatternHit,
  ScriptPatternId,
  SecurityFinding,
} from "../shared/types";

const PATTERN_LABELS: Record<ScriptPatternId, string> = {
  "eval-call": "eval() call",
  "atob-call": "Base64 decoding (atob)",
  "from-char-code": "String.fromCharCode construction",
  "document-write": "document.write()",
  "unescape-call": "unescape() decoding",
  "hex-escape-density": "Dense hexadecimal escapes",
  "long-base64": "Long embedded Base64-like string",
  "clipboard-listener": "Clipboard event listener",
  "keyboard-listener": "Keyboard event listener",
  "form-action-write": "Script writes a form action",
  "location-write": "Script writes location",
  "dynamic-script-create": "Dynamic script element creation",
  "inline-handler": "Inline event handler",
};

const STRONG_PATTERNS: ScriptPatternId[] = [
  "eval-call",
  "atob-call",
  "from-char-code",
  "document-write",
  "unescape-call",
  "hex-escape-density",
  "long-base64",
  "dynamic-script-create",
];

const KEYBOARD_HANDLERS = /^(onkeydown|onkeypress|onkeyup)$/i;
const CLIPBOARD_HANDLERS = /^(onpaste|oncopy|oncut)$/i;

function aggregatePatterns(scripts: ScriptMetadata[]): ScriptPatternHit[] {
  const map = new Map<ScriptPatternId, ScriptPatternHit>();
  for (const script of scripts) {
    for (const hit of script.patterns) {
      const existing = map.get(hit.id);
      if (existing) {
        existing.count += hit.count;
      } else {
        map.set(hit.id, { ...hit });
      }
    }
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count);
}

export interface ScriptAnalysisOptions {
  credentialForm: boolean;
  phishingScore?: number;
}

export function analyzeScripts(
  evidence: PageEvidence | null,
  options: ScriptAnalysisOptions,
): ScriptAnalysis {
  const limitations = [
    "Script inspection uses static signatures and observable DOM metadata only. Code is never executed or fetched.",
    "Inline script content is not stored; only pattern identifiers and counts are retained.",
    "A keyboard or clipboard event listener is common on legitimate sites and is not proof of a keylogger.",
    "Scripts can be injected or changed after analysis, and cross-origin script bodies are not observable.",
  ];

  if (!evidence) {
    return {
      available: false,
      externalScriptCount: 0,
      inlineScriptCount: 0,
      thirdPartyScriptHosts: [],
      inlinePatternHits: [],
      sensitiveInputHandlers: [],
      clipboardIndicators: 0,
      keyboardIndicators: 0,
      suspiciousOverlay: false,
      suspiciousOverlayEvidence: [],
      risk: "none",
      confidence: "low",
      findings: [],
      limitations: [...limitations, "Page script evidence is unavailable, so script risk is unknown rather than safe."],
    };
  }

  const external = evidence.scripts.filter((script) => !script.inline && script.src);
  const inlineScripts = evidence.scripts.filter((script) => script.inline);
  const patternHits = aggregatePatterns(evidence.scripts);
  const thirdPartyScriptHosts = Array.from(
    new Set(
      external
        .filter((script) => !script.firstParty && script.host)
        .map((script) => script.host as string),
    ),
  ).sort();

  const handlers = evidence.sensitiveInputHandlers;
  const clipboardIndicators =
    (patternHits.find((hit) => hit.id === "clipboard-listener")?.count ?? 0) +
    evidence.clipboardHandlerIndicators.length;
  const keyboardIndicators =
    (patternHits.find((hit) => hit.id === "keyboard-listener")?.count ?? 0) +
    handlers.filter((handler) => KEYBOARD_HANDLERS.test(handler.handler)).length;
  const clipboardOnFields = handlers.filter((handler) => CLIPBOARD_HANDLERS.test(handler.handler)).length;

  const strongHits = patternHits.filter(
    (hit) => STRONG_PATTERNS.includes(hit.id) && hit.count > 0,
  );
  const distinctStrong = new Set(strongHits.map((hit) => hit.id)).size;
  const multiple = distinctStrong >= 2;
  const single = distinctStrong === 1;

  const findings: SecurityFinding[] = [];
  let risk: ScriptAnalysis["risk"] = "none";
  let confidence: ScriptAnalysis["confidence"] = "low";

  if (multiple) {
    risk = "high";
    confidence = "high";
    findings.push({
      id: "script:multiple-obfuscation-indicators",
      category: "script",
      severity: "high",
      confidence: "high",
      title: "Multiple obfuscation-related script indicators",
      explanation: `Inline scripts contain ${distinctStrong} distinct patterns commonly used to hide or generate code (${strongHits
        .slice(0, 4)
        .map((hit) => PATTERN_LABELS[hit.id])
        .join(", ")}). Legitimate minifiers can trigger some of these, but the combination on a credential page warrants caution.`,
      evidence: strongHits
        .slice(0, 6)
        .map((hit) => `${PATTERN_LABELS[hit.id]} ×${hit.count}`),
      remediation:
        "Do not enter credentials if the page also shows domain or form-destination warnings. Leave the site if you arrived from an unsolicited message.",
      source: "local-heuristic",
      penalty: PENALTIES.multipleMaliciousScripts,
    });
  } else if (single) {
    const hit = strongHits[0];
    const label = hit ? PATTERN_LABELS[hit.id] : "Suspicious script pattern";
    risk = options.credentialForm ? "medium" : "low";
    confidence = "medium";
    findings.push({
      id: "script:single-obfuscation-indicator",
      category: "script",
      severity: options.credentialForm ? "medium" : "low",
      confidence: "medium",
      title: "Obfuscation-related script pattern detected",
      explanation: `${label} was found in inline script${options.credentialForm ? " on a page containing a credential form" : ""}. Obfuscation is also used by legitimate analytics and app bundles; this is a signal, not proof of malice.`,
      evidence: hit ? [`${PATTERN_LABELS[hit.id]} ×${hit.count}`] : [],
      remediation: "Verify the site's identity through an independent source before entering sensitive information.",
      source: "local-heuristic",
      penalty: options.credentialForm ? PENALTIES.suspiciousScript : 0,
    });
  }

  if ((clipboardIndicators > 0 || clipboardOnFields > 0) && options.credentialForm) {
    risk = risk === "high" ? "high" : "medium";
    confidence = "medium";
    findings.push({
      id: "script:clipboard-handler-credentials",
      category: "script",
      severity: "medium",
      confidence: "medium",
      title: "Clipboard handler present near a credential form",
      explanation:
        "A script or inline handler registers clipboard-related events on a page that collects credentials. This can support legitimate paste handling, but the behavior requires investigation. Sentinel cannot observe whether clipboard contents are read or transmitted.",
      evidence: [
        ...evidence.clipboardHandlerIndicators.slice(0, 4),
        ...(clipboardOnFields > 0 ? [`${clipboardOnFields} clipboard handler(s) on sensitive inputs`] : []),
      ].slice(0, 6),
      remediation:
        "Avoid pasting passwords or one-time codes on an unverified page. Use the site's official app or an independently obtained address.",
      source: "observed",
      penalty: PENALTIES.suspiciousScript,
    });
  } else if (clipboardIndicators > 0) {
    findings.push({
      id: "script:clipboard-handler",
      category: "script",
      severity: "info",
      confidence: "low",
      title: "Clipboard event handler detected",
      explanation:
        "A clipboard-related event listener is present. This is common in editors and forms and is not evidence of clipboard theft by itself.",
      evidence: evidence.clipboardHandlerIndicators.slice(0, 4),
      remediation: "No action required unless other suspicious indicators are present.",
      source: "observed",
      penalty: 0,
    });
  }

  if (keyboardIndicators > 0 && options.credentialForm && multiple) {
    findings.push({
      id: "script:keyboard-handler-combined",
      category: "script",
      severity: "low",
      confidence: "low",
      title: "Keyboard handlers combined with obfuscation",
      explanation:
        "Keyboard event handlers are normal on many sites and are not proof of a keylogger. Their presence alongside multiple obfuscation indicators modestly increases risk.",
      evidence: [`${keyboardIndicators} keyboard handler indicator(s)`],
      remediation: "Review the other high-severity findings before entering data.",
      source: "local-heuristic",
      penalty: 0,
    });
  }

  if (evidence.suspiciousOverlay && evidence.passwordFieldCount > 0) {
    findings.push({
      id: "script:credential-overlay",
      category: "script",
      severity: "low",
      confidence: "low",
      title: "Credential field inside a fixed overlay",
      explanation:
        "A password field appears inside a fixed or sticky overlay. Many legitimate sites use modal login dialogs. Treat this only as a weak contextual indicator.",
      evidence: evidence.suspiciousOverlayEvidence.slice(0, 4),
      remediation: "Confirm the page address and the site's identity before continuing.",
      source: "observed",
      penalty: 0,
    });
  }

  const actionWrites = patternHits.find((hit) => hit.id === "form-action-write");
  if (actionWrites) {
    findings.push({
      id: "script:form-action-write",
      category: "script",
      severity: "info",
      confidence: "low",
      title: "Script can modify form destinations",
      explanation:
        "Inline script contains a pattern that writes a form action. This is common in legitimate single-page applications; Sentinel separately reports forms whose action actually changed after load.",
      evidence: [`${PATTERN_LABELS["form-action-write"]} ×${actionWrites.count}`],
      remediation: "No action required unless a form-destination warning is also shown.",
      source: "local-heuristic",
      penalty: 0,
    });
  }

  if (risk === "none" && (multiple || single)) risk = "low";

  return {
    available: true,
    externalScriptCount: external.length,
    inlineScriptCount: inlineScripts.length,
    thirdPartyScriptHosts,
    inlinePatternHits: patternHits.map((hit) => ({
      id: hit.id,
      label: PATTERN_LABELS[hit.id],
      count: hit.count,
      confidence: hit.confidence,
    })),
    sensitiveInputHandlers: handlers,
    clipboardIndicators,
    keyboardIndicators,
    suspiciousOverlay: evidence.suspiciousOverlay,
    suspiciousOverlayEvidence: evidence.suspiciousOverlayEvidence,
    risk,
    confidence,
    findings,
    limitations,
  };
}
