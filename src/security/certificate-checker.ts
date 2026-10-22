export interface TlsObservation {
  status: "browser-https" | "browser-http" | "unknown";
  summary: string;
  limitations: string[];
}

/**
 * Sentinel does not attempt to validate certificates itself. Standard extension
 * APIs do not expose the full TLS chain, so the browser's own validation is the
 * authority. This module only reports what the browser allowed to load.
 */
export function observeBrowserTls(protocol: string, pageLoaded: boolean): TlsObservation {
  if (!pageLoaded) {
    return {
      status: "unknown",
      summary: "Connection status could not be observed for this tab.",
      limitations: [
        "Sentinel only assesses pages the browser has loaded and exposed to the extension.",
        "Browser certificate errors are handled by Chromium and are not separately reported to the extension.",
      ],
    };
  }
  if (protocol === "https:") {
    return {
      status: "browser-https",
      summary:
        "The browser loaded this page over HTTPS. Chromium accepted the connection; Sentinel did not independently inspect the certificate chain.",
      limitations: [
        "A valid HTTPS connection protects data in transit but does not prove the site owner is trustworthy.",
        "Extensions cannot read the complete certificate chain or independently re-validate every certificate field.",
        "If Chromium blocks a certificate error, the page may not load and Sentinel cannot report the certificate error itself.",
      ],
    };
  }
  if (protocol === "http:") {
    return {
      status: "browser-http",
      summary: "This page was loaded over unencrypted HTTP. Data in transit can be read or modified by network parties.",
      limitations: [
        "HTTP alone does not mean the site is malicious; many informational or legacy sites still use it.",
        "HTTPS's absence is a transport-security issue, not proof of fraud.",
      ],
    };
  }
  return {
    status: "unknown",
    summary: "This protocol is not assessed by Sentinel.",
    limitations: ["Only http:// and https:// pages are inspected."],
  };
}
