import { findTrustedProvider } from "../data/trusted-providers";
import type {
  Confidence,
  FormAnalysis,
  FormFlag,
  FormMetadata,
  FormRelationship,
  SensitiveFieldKind,
} from "../shared/types";

const HIGH_IMPACT_KINDS = new Set<SensitiveFieldKind>([
  "password",
  "otp",
  "card",
  "security-code",
  "national-id",
]);

export interface FormAnalysisOptions {
  pageUrl: string;
}

function safeOrigin(value: string | null): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? url.origin : null;
  } catch {
    return null;
  }
}

function bumpRisk(current: FormAnalysis["risk"], next: FormAnalysis["risk"]): FormAnalysis["risk"] {
  const order: FormAnalysis["risk"][] = ["none", "low", "medium", "high", "critical"];
  return order.indexOf(next) > order.indexOf(current) ? next : current;
}

export function analyzeForms(forms: FormMetadata[] | null, options: FormAnalysisOptions): FormAnalysis[] {
  if (!forms) return [];
  const pageOrigin = safeOrigin(options.pageUrl);
  if (!pageOrigin) return [];

  return forms.map((form) => {
    const reasons: string[] = [];
    const limitations = [
      "Only the initial form action is observable. Scripts or server redirects can change the final recipient.",
      "Form values were never read, stored, or submitted.",
      "Destination ownership was not independently verified.",
    ];
    const flags: FormFlag[] = [];
    let risk: FormAnalysis["risk"] = "none";
    let confidence: Confidence = "medium";
    let relationship: FormRelationship = "unknown";
    let trustedProvider: string | null = null;
    const sensitiveKinds = Array.from(new Set(form.fieldKinds));
    const hasHighImpact = sensitiveKinds.some((kind) => HIGH_IMPACT_KINDS.has(kind));

    if (form.actionIsJavascript) {
      reasons.push("The form action uses a javascript: URL, which hides the true destination.");
      risk = "high";
      confidence = "high";
      flags.push("action-javascript");
      limitations.push("The final recipient cannot be determined from a javascript: action.");
    } else if (form.actionMissing || !form.action) {
      reasons.push(
        "No explicit destination is set. The browser would submit to the current page, unless a script changes or handles the submission.",
      );
      relationship = "unknown";
      confidence = "low";
      risk = sensitiveKinds.length > 0 ? "low" : "none";
      flags.push("action-missing");
      limitations.push("The destination cannot be verified because no action attribute is present.");
    } else {
      const destinationOrigin = safeOrigin(form.action);
      const destinationHost = form.actionHost;
      if (!destinationOrigin || !destinationHost) {
        relationship = "unknown";
        risk = sensitiveKinds.length > 0 ? "medium" : "low";
        reasons.push("The form destination could not be parsed reliably.");
        confidence = "low";
        flags.push("destination-unknown");
      } else {
        const provider = findTrustedProvider(destinationHost);
        trustedProvider = provider?.label ?? null;
        const isHttpsPage = pageOrigin.startsWith("https:");
        const isInsecureAction = form.action.startsWith("http:") && isHttpsPage;

        if (destinationOrigin === pageOrigin) {
          relationship = "same-origin";
          confidence = "high";
          flags.push("same-origin");
          if (provider) trustedProvider = provider.label;
          if (sensitiveKinds.length > 0 && form.method === "GET") {
            risk = "medium";
            flags.push("get-sensitive");
            reasons.push(
              "A form containing sensitive fields uses GET. Browsers may place submitted values in the URL, where they can leak through history, logs, or referrers.",
            );
          } else {
            reasons.push("The form submits to the same origin as the page.");
          }
        } else if (isInsecureAction) {
          relationship = "insecure";
          risk = hasHighImpact ? "high" : "medium";
          confidence = "high";
          flags.push("insecure-action");
          reasons.push(
            "This HTTPS page submits the form to an unencrypted HTTP destination. Data could be exposed in transit.",
          );
        } else if (provider) {
          relationship = "cross-origin";
          risk = "low";
          confidence = "high";
          flags.push("cross-origin-external", "trusted-provider");
          reasons.push(
            `The form submits to ${provider.label}, a commonly used ${provider.kind} provider. This requires verification but is not evidence of malicious behavior.`,
          );
        } else {
          relationship = "cross-origin";
          confidence = hasHighImpact ? "high" : "medium";
          flags.push("cross-origin-external");
          if (hasHighImpact) {
            risk = "high";
            flags.push("external-sensitive");
            reasons.push(
              "A form with credentials or payment fields submits to an unrelated external origin. Legitimate sites sometimes do this, but it must be verified before entering sensitive data.",
            );
          } else if (sensitiveKinds.length > 0) {
            risk = "medium";
            flags.push("external-account");
            reasons.push(
              "A form containing account or contact fields submits to an unrelated external origin. Verify the destination before submitting.",
            );
          } else {
            risk = "low";
            reasons.push("The form submits to a different origin without sensitive fields.");
          }
        }
      }
    }

    if (form.actionChanged) {
      risk = bumpRisk(risk, "medium");
      flags.push("action-changed");
      reasons.push("The form action changed after the page loaded. This can be legitimate, but it obscures the destination.");
      limitations.push("The previous and current actions were compared in the page only; redirects after submission remain unobservable.");
    }

    if (form.inlineSubmitHandler) {
      limitations.push("An inline submit handler is present; JavaScript may alter where data is sent.");
    }

    return {
      formIndex: form.index,
      pageOrigin,
      destinationOrigin: form.action ? safeOrigin(form.action) : null,
      destinationHost: form.actionHost,
      relationship,
      trustedProvider,
      sensitiveKinds,
      risk,
      confidence,
      reasons,
      limitations,
      requiresVerification:
        risk === "high" || risk === "critical" || relationship === "cross-origin" || relationship === "insecure",
      flags,
    };
  });
}
