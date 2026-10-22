import type { FormMetadata, PageEvidence, ScriptMetadata, ScriptPatternId, SensitiveFieldKind, SensitiveInputHandler, ObservedResource } from "../shared/types";

const sensitiveTerms: Array<[SensitiveFieldKind, RegExp]> = [
  ["password", /password|passwd|passcode/i], ["email", /email|e-mail/i], ["username", /user(name)?|login|account/i],
  ["otp", /otp|one[- ]time|verification code|authenticator/i], ["card", /card number|cc-number|credit card/i], ["security-code", /cvv|cvc|security code/i], ["national-id", /ssn|social security|national id/i],
];
const safeUrl = (value: string) => { try { const url = new URL(value, location.href); return url.protocol === "http:" || url.protocol === "https:" ? `${url.protocol}//${url.host}${url.pathname}` : null; } catch { return null; } };
const labelText = (element: HTMLInputElement) => {
  const associatedLabels = element.labels ? Array.from(element.labels).map((label) => label.textContent ?? "").join(" ") : "";
  return `${element.name} ${element.id} ${element.placeholder} ${element.autocomplete} ${element.getAttribute("aria-label") ?? ""} ${associatedLabels}`;
};
function classifyInput(input: HTMLInputElement): SensitiveFieldKind | null { const text = labelText(input); if (input.type === "password") return "password"; for (const [kind, pattern] of sensitiveTerms) if (pattern.test(text)) return kind; return null; }
function patternHits(text: string): ScriptMetadata["patterns"] { const patterns: Array<[ScriptPatternId, RegExp, string]> = [["eval-call", /\beval\s*\(/g, "eval() call"], ["atob-call", /\batob\s*\(/g, "Base64 decoding"], ["from-char-code", /String\.fromCharCode/g, "Character-code construction"], ["document-write", /document\.write\s*\(/g, "document.write()"], ["unescape-call", /\bunescape\s*\(/g, "unescape() decoding"], ["long-base64", /[A-Za-z0-9+/]{160,}={0,2}/g, "Long Base64-like string"], ["form-action-write", /\.action\s*=/g, "Form action write"], ["location-write", /location\s*=|location\.href\s*=/g, "Location write"], ["dynamic-script-create", /createElement\s*\(\s*["']script/g, "Dynamic script creation"]]; return patterns.flatMap(([id, regex, label]) => { const count = text.match(regex)?.length ?? 0; return count ? [{ id, label, count, confidence: count > 1 ? "medium" : "low" }] : []; }); }
function inspect(): PageEvidence {
  const pageOrigin = `${location.protocol}//${location.host}`;
  const forms: FormMetadata[] = Array.from(document.forms).slice(0, 30).map((form, index) => { const fields = Array.from(form.elements).filter((element): element is HTMLInputElement => element instanceof HTMLInputElement).map((input) => { const kind = classifyInput(input); return kind ? { kind, fieldType: input.type, autocomplete: input.autocomplete || null, hasLabel: Boolean(input.labels?.length) } : null; }).filter((field): field is NonNullable<typeof field> => Boolean(field)); const actionRaw = form.getAttribute("action"); const actionIsJavascript = Boolean(actionRaw && /^javascript:/i.test(actionRaw)); const action = actionIsJavascript ? null : safeUrl(form.action || location.href); let actionHost: string | null = null; try { actionHost = action ? new URL(action).hostname : null; } catch { /* sanitized below */ } const kinds = Array.from(new Set(fields.map((field) => field.kind))); return { index, action, actionHost, actionMissing: !actionRaw, actionIsJavascript, actionChanged: false, method: (form.method || "GET").toUpperCase(), target: form.target || null, hasPassword: kinds.includes("password"), hasSensitive: kinds.length > 0, hasOtp: kinds.includes("otp"), hasCard: kinds.includes("card"), hasNationalId: kinds.includes("national-id"), hasHiddenFields: Boolean(form.querySelector('input[type="hidden"]')), fieldKinds: kinds, fields, submitControl: form.querySelector("button") ? "button" : form.querySelector('input[type="submit"]') ? "input" : "none", inlineSubmitHandler: Boolean(form.getAttribute("onsubmit")) }; });
  const scripts: ScriptMetadata[] = Array.from(document.scripts).slice(0, 250).map((script) => { const src = script.src ? safeUrl(script.src) : null; let host: string | null = null; try { host = src ? new URL(src).hostname : null; } catch { /* ignore */ } const inline = !script.src; return { src, host, firstParty: !host || host === location.hostname, inline, inlineLength: inline ? (script.textContent?.length ?? 0) : 0, patterns: inline ? patternHits(script.textContent ?? "") : [] }; });
  const resources = Array.from(document.querySelectorAll<HTMLImageElement | HTMLIFrameElement | HTMLLinkElement | HTMLScriptElement | HTMLMediaElement | HTMLEmbedElement | HTMLObjectElement>("img,iframe,link[src],link[href],script[src],audio[src],video[src],source[src],embed[src],object[data]"))
    .slice(0, 400)
    .flatMap((element): ObservedResource[] => {
      const raw = element instanceof HTMLLinkElement ? element.href : element instanceof HTMLObjectElement ? element.data : element.src;
      const url = safeUrl(raw);
      if (!url) return [];
      let host = "";
      try { host = new URL(url).hostname; } catch { return []; }
      return [{ host, url, type: element.tagName.toLowerCase(), count: 1, firstParty: host === location.hostname }];
    });
  const sensitiveInputHandlers: SensitiveInputHandler[] = []; for (const input of document.querySelectorAll<HTMLInputElement>("input")) { const kind = classifyInput(input); if (!kind) continue; for (const handler of ["onpaste", "oncopy", "oncut", "onkeydown", "onkeypress", "onkeyup"]) if (input.getAttribute(handler)) sensitiveInputHandlers.push({ kind, handler }); }

  const iframes = Array.from(document.querySelectorAll("iframe"));
  const hiddenIframes = iframes.filter((iframe) => {
    try {
      const style = window.getComputedStyle(iframe);
      const rect = iframe.getBoundingClientRect();
      return style.display === "none" || style.visibility === "hidden" || style.opacity === "0" || (rect.width > 0 && rect.width < 5 && rect.height > 0 && rect.height < 5);
    } catch {
      return false;
    }
  });
  const hiddenIframeCount = hiddenIframes.length;
  const hiddenIframeExamples = hiddenIframes.slice(0, 8).map((iframe) => safeUrl(iframe.src) ?? "hidden-iframe").filter(Boolean);

  const inputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
  const hasPassword = inputs.some((input) => input.type === "password");
  const hasUser = inputs.some((input) => /email|user(name)?|login|account/i.test(labelText(input)));
  let brandMismatchDetected = false;
  let brandMismatchBrand: string | null = null;
  const brandMismatchEvidence: string[] = [];

  if (hasPassword && hasUser) {
    const pageIdentityText = [
      document.title,
      Array.from(document.querySelectorAll("h1, h2")).map((el) => el.textContent).join(" "),
      Array.from(document.querySelectorAll("img")).map((img) => img.alt).join(" "),
      document.querySelector('meta[name="description"]')?.getAttribute("content") ?? "",
    ].join(" ").toLowerCase();

    for (const brand of ["paypal", "amazon", "google", "microsoft", "apple", "facebook", "netflix", "chase", "wellsfargo"]) {
      if (pageIdentityText.includes(brand)) {
        const host = location.hostname.toLowerCase();
        const isLegit = host.includes(brand) || host.endsWith(`.${brand}.com`) || host === `${brand}.com`;
        if (!isLegit) {
          brandMismatchDetected = true;
          brandMismatchBrand = brand;
          brandMismatchEvidence.push(`Brand "${brand}" is prominent in page headings/identity but hostname is "${location.hostname}".`);
          break;
        }
      }
    }
  }

  return { url: safeUrl(location.href) ?? location.href, origin: pageOrigin, title: document.title, isTopFrame: window.top === window, collectedAt: Date.now(), forms, scripts, resources, mixedContentCount: location.protocol === "https:" ? resources.filter((item) => item.url.startsWith("http:")).length : 0, mixedContentExamples: resources.filter((item) => item.url.startsWith("http:")).slice(0, 8).map((item) => item.url), sensitiveInputCount: document.querySelectorAll("input").length, passwordFieldCount: document.querySelectorAll('input[type="password"]').length, sensitiveInputHandlers, clipboardHandlerIndicators: [], suspiciousOverlay: false, suspiciousOverlayEvidence: [], iframeCount: iframes.length, hiddenIframeCount, hiddenIframeExamples, brandMismatchDetected, brandMismatchBrand, brandMismatchEvidence, limitations: ["Only metadata was collected. Field values, keystrokes, clipboard contents, and script bodies are not stored."] };
}
let publishTimer: number | undefined;
function publish() {
  if (publishTimer !== undefined) window.clearTimeout(publishTimer);
  publishTimer = window.setTimeout(() => {
    publishTimer = undefined;
    void chrome.runtime.sendMessage({ type: "PAGE_EVIDENCE", evidence: inspect() });
  }, 400);
}
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => { if (message?.type === "REQUEST_EVIDENCE") { sendResponse({ evidence: inspect() }); return true; } if (message?.type === "SNAPSHOT_UPDATED" && message.assessment?.critical) showWarning(message.assessment.topFactors?.[0] ?? "High-confidence risk evidence was observed."); return false; });
function showWarning(reason: string) { if (document.getElementById("sentinel-warning")) return; const panel = document.createElement("aside"); panel.id = "sentinel-warning"; panel.setAttribute("role", "alertdialog"); panel.style.cssText = "position:fixed;z-index:2147483647;inset:18px 18px auto auto;max-width:380px;padding:18px;background:#101827;color:#f8fafc;border:1px solid #ef4444;border-radius:14px;box-shadow:0 12px 40px #0008;font:14px system-ui"; const title = document.createElement("strong"); title.textContent = "Sentinel warning"; const body = document.createElement("p"); body.textContent = reason; const close = document.createElement("button"); close.textContent = "Dismiss"; close.style.cssText = "padding:8px 12px;background:#24344f;color:#fff;border:0;border-radius:8px"; close.addEventListener("click", () => panel.remove()); panel.append(title, body, close); document.documentElement.append(panel); }
document.addEventListener("submit", (event) => {
  const form = event.target instanceof HTMLFormElement ? event.target : null;
  if (!form) return;
  const metadata = inspect().forms.find((candidate) => candidate.index === Array.from(document.forms).indexOf(form));
  if (!metadata?.hasSensitive) return;
  event.preventDefault();
  void chrome.runtime.sendMessage({ type: "CHECK_SUBMISSION", input: { pageUrl: location.href, formIndex: metadata.index, action: metadata.action, actionHost: metadata.actionHost, actionChanged: metadata.actionChanged, method: metadata.method, fieldKinds: metadata.fieldKinds, hasPassword: metadata.hasPassword, hasOtp: metadata.hasOtp, hasCard: metadata.hasCard } }).then((response) => {
    if (response?.decision?.decision !== "warn") { form.submit(); return; }
    showWarning(`${response.decision.title}. ${response.decision.summary} ${response.decision.reasons?.join(" ") ?? ""}`);
  }).catch(() => { showWarning("Sentinel could not complete the submission safety check. Do not continue until the destination is verified."); });
}, true);
publish();
window.addEventListener("DOMContentLoaded", publish, { once: true });
window.addEventListener("load", publish, { once: true });
new MutationObserver(() => publish()).observe(document.documentElement, { subtree: true, childList: true, attributes: true, attributeFilter: ["action", "onsubmit", "name", "id", "type", "autocomplete", "aria-label"] });
