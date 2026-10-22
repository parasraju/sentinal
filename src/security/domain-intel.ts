import { PENALTIES } from "../shared/constants";
import type { DomainIntelReport, SecurityFinding } from "../shared/types";

export interface DomainIntelOptions {
  timeoutMs?: number;
  now?: number;
  fetchFn?: typeof fetch;
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  timeoutMs: number,
  fetchFn: typeof fetch,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchFn(url, { ...options, signal: controller.signal });
    clearTimeout(timeoutId);
    return response;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

export async function analyzeDomainIntel(
  domain: string | null,
  options: DomainIntelOptions = {},
): Promise<DomainIntelReport> {
  const now = options.now ?? Date.now();
  const timeoutMs = options.timeoutMs ?? 5000;
  const fetchFn = options.fetchFn ?? globalThis.fetch;

  const emptyReport: DomainIntelReport = {
    available: false,
    domain: domain ?? "unknown",
    domainAgeDays: null,
    registrationDate: null,
    expiryDate: null,
    registrar: null,
    ctCertAgeDays: null,
    ctCertTotal: null,
    ctIssuers: [],
    hasSpf: false,
    hasDmarc: false,
    dmarcPolicy: null,
    mxRecords: [],
    aRecords: [],
    findings: [],
    limitations: [
      "RDAP, Certificate Transparency, and DoH checks rely on public registries and network availability.",
      "An unavailable lookup is never treated as proof of safety or guilt.",
    ],
    error: null,
  };

  if (!domain || domain === "unknown" || !fetchFn) {
    return emptyReport;
  }

  const cleanDomain = domain.toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
  const findings: SecurityFinding[] = [];
  const limitations = [...emptyReport.limitations];
  let available = false;
  let rdapError: string | null = null;

  let domainAgeDays: number | null = null;
  let registrationDate: string | null = null;
  let expiryDate: string | null = null;
  let registrar: string | null = null;

  let ctCertAgeDays: number | null = null;
  let ctCertTotal: number | null = null;
  const ctIssuers: string[] = [];

  let hasSpf = false;
  let hasDmarc = false;
  let dmarcPolicy: string | null = null;
  const mxRecords: string[] = [];
  const aRecords: string[] = [];

  // Run RDAP, crt.sh CT, and DNS DoH queries in parallel
  const [rdapRes, ctRes, mxDohRes, txtDohRes, dmarcDohRes, aDohRes] = await Promise.allSettled([
    // 1. RDAP Domain Registration Data (RFC 7480)
    fetchWithTimeout(
      `https://rdap.org/domain/${encodeURIComponent(cleanDomain)}`,
      { headers: { Accept: "application/rdap+json, application/json" } },
      timeoutMs,
      fetchFn,
    ).then((r) => (r.ok ? r.json() : Promise.reject(new Error(`RDAP ${r.status}`)))),

    // 2. Certificate Transparency via crt.sh
    fetchWithTimeout(
      `https://crt.sh/?q=${encodeURIComponent(cleanDomain)}&output=json`,
      { headers: { Accept: "application/json" } },
      timeoutMs,
      fetchFn,
    ).then((r) => (r.ok ? r.json() : Promise.reject(new Error(`crt.sh ${r.status}`)))),

    // 3. Cloudflare DoH MX Records
    fetchWithTimeout(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=MX`,
      { headers: { Accept: "application/dns-json" } },
      timeoutMs,
      fetchFn,
    ).then((r) => (r.ok ? r.json() : null)),

    // 4. Cloudflare DoH TXT Records (SPF)
    fetchWithTimeout(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=TXT`,
      { headers: { Accept: "application/dns-json" } },
      timeoutMs,
      fetchFn,
    ).then((r) => (r.ok ? r.json() : null)),

    // 5. Cloudflare DoH TXT Records for DMARC
    fetchWithTimeout(
      `https://cloudflare-dns.com/dns-query?name=_dmarc.${encodeURIComponent(cleanDomain)}&type=TXT`,
      { headers: { Accept: "application/dns-json" } },
      timeoutMs,
      fetchFn,
    ).then((r) => (r.ok ? r.json() : null)),

    // 6. Cloudflare DoH A Records
    fetchWithTimeout(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=A`,
      { headers: { Accept: "application/dns-json" } },
      timeoutMs,
      fetchFn,
    ).then((r) => (r.ok ? r.json() : null)),
  ]);

  // Process RDAP Result
  if (rdapRes.status === "fulfilled" && rdapRes.value) {
    available = true;
    const rdapData = rdapRes.value as Record<string, unknown>;
    const events = Array.isArray(rdapData.events) ? rdapData.events : [];
    for (const event of events) {
      if (typeof event === "object" && event !== null) {
        const e = event as { eventAction?: string; eventDate?: string };
        if (e.eventAction === "registration" && e.eventDate) {
          registrationDate = e.eventDate;
        } else if (e.eventAction === "expiration" && e.eventDate) {
          expiryDate = e.eventDate;
        }
      }
    }

    if (Array.isArray(rdapData.entities)) {
      const registrarEntity = (rdapData.entities as Array<Record<string, unknown>>).find((e) =>
        Array.isArray(e.roles) && (e.roles as string[]).includes("registrar"),
      );
      if (registrarEntity && Array.isArray(registrarEntity.vcardArray)) {
        const card = registrarEntity.vcardArray[1];
        if (Array.isArray(card)) {
          const fn = (card as Array<unknown[]>).find((v) => Array.isArray(v) && v[0] === "fn");
          if (fn && typeof fn[3] === "string") {
            registrar = fn[3];
          }
        }
      }
    }

    if (registrationDate) {
      const regTime = new Date(registrationDate).getTime();
      if (!Number.isNaN(regTime)) {
        domainAgeDays = Math.max(0, Math.floor((now - regTime) / (1000 * 60 * 60 * 24)));
        if (domainAgeDays < 14) {
          findings.push({
            id: "domain:very-young",
            category: "domain",
            severity: "high",
            confidence: "high",
            title: "Domain registered less than 14 days ago",
            explanation: `This domain was registered on ${new Date(registrationDate).toLocaleDateString()} (${domainAgeDays} day${domainAgeDays === 1 ? "" : "s"} ago). Newly registered domains carry elevated risk as they are frequently used in short-lived phishing attacks.`,
            evidence: [`Registration date: ${registrationDate}`, `Domain: ${cleanDomain}`, `Age: ${domainAgeDays} days`],
            remediation: "Verify the sender and destination identity independently before submitting credentials or sensitive information.",
            source: "observed",
            penalty: PENALTIES.domainAgeVeryYoung,
          });
        } else if (domainAgeDays < 30) {
          findings.push({
            id: "domain:young",
            category: "domain",
            severity: "medium",
            confidence: "high",
            title: "Domain registered less than 30 days ago",
            explanation: `This domain was registered ${domainAgeDays} days ago (${new Date(registrationDate).toLocaleDateString()}). Most legitimate banking and commercial institutions operate on established domains.`,
            evidence: [`Registration date: ${registrationDate}`, `Age: ${domainAgeDays} days`],
            remediation: "Confirm the website through official communications before sharing sensitive data.",
            source: "observed",
            penalty: PENALTIES.domainAgeYoung,
          });
        } else if (domainAgeDays < 90) {
          findings.push({
            id: "domain:moderate-age",
            category: "domain",
            severity: "info",
            confidence: "medium",
            title: "Domain registered within the last 90 days",
            explanation: `This domain is relatively new (${domainAgeDays} days old). While many new sites are legitimate, proceed with normal caution.`,
            evidence: [`Registration date: ${registrationDate}`, `Age: ${domainAgeDays} days`],
            remediation: "Standard caution is advised.",
            source: "observed",
            penalty: PENALTIES.domainAgeModerate,
          });
        }
      }
    }
  } else if (rdapRes.status === "rejected") {
    rdapError = rdapRes.reason instanceof Error ? rdapRes.reason.message : "RDAP request failed";
  }

  // Process Certificate Transparency Result (crt.sh)
  if (ctRes.status === "fulfilled" && Array.isArray(ctRes.value) && ctRes.value.length > 0) {
    available = true;
    const certs = ctRes.value as Array<{ not_before?: string; entry_timestamp?: string; issuer_name?: string }>;
    ctCertTotal = certs.length;
    const timestamps = certs
      .map((c) => {
        const timeStr = c.not_before || c.entry_timestamp;
        return timeStr ? new Date(timeStr).getTime() : NaN;
      })
      .filter((t) => !Number.isNaN(t))
      .sort((a, b) => b - a);

    for (const c of certs) {
      if (c.issuer_name && !ctIssuers.includes(c.issuer_name)) {
        ctIssuers.push(c.issuer_name);
        if (ctIssuers.length >= 3) break;
      }
    }

    if (timestamps.length > 0) {
      const newestCertTime = timestamps[0]!;
      ctCertAgeDays = Math.max(0, Math.floor((now - newestCertTime) / (1000 * 60 * 60 * 24)));

      if (ctCertAgeDays < 7) {
        findings.push({
          id: "cert:recently-issued",
          category: "connection",
          severity: "medium",
          confidence: "medium",
          title: "TLS certificate issued less than 7 days ago",
          explanation: `Public Certificate Transparency logs indicate the newest certificate for this domain was issued ${ctCertAgeDays} day${ctCertAgeDays === 1 ? "" : "s"} ago. Recent issuance is common on newly deployed phishing infrastructure.`,
          evidence: [`Newest cert issuance: ${new Date(newestCertTime).toLocaleDateString()}`, `Issuers: ${ctIssuers.join(", ") || "Unknown"}`],
          remediation: "Ensure the organization identity matches expectations before logging in.",
          source: "observed",
          penalty: PENALTIES.ctCertVeryYoung,
        });
      } else if (ctCertAgeDays < 30) {
        findings.push({
          id: "cert:young",
          category: "connection",
          severity: "info",
          confidence: "low",
          title: "TLS certificate issued recently",
          explanation: `The active certificate for this domain was issued ${ctCertAgeDays} days ago.`,
          evidence: [`Newest cert issuance: ${new Date(newestCertTime).toLocaleDateString()}`],
          remediation: "Informational only.",
          source: "observed",
          penalty: PENALTIES.ctCertYoung,
        });
      }
    }
  }

  // Process DoH MX
  if (mxDohRes.status === "fulfilled" && mxDohRes.value?.Answer) {
    available = true;
    for (const ans of mxDohRes.value.Answer as Array<{ data?: string }>) {
      if (ans.data) mxRecords.push(ans.data);
    }
  }

  // Process DoH A Records
  if (aDohRes.status === "fulfilled" && aDohRes.value?.Answer) {
    available = true;
    for (const ans of aDohRes.value.Answer as Array<{ data?: string }>) {
      if (ans.data) aRecords.push(ans.data);
    }
  }

  // Process DoH SPF
  if (txtDohRes.status === "fulfilled" && txtDohRes.value?.Answer) {
    available = true;
    for (const ans of txtDohRes.value.Answer as Array<{ data?: string }>) {
      if (ans.data && ans.data.includes("v=spf1")) {
        hasSpf = true;
        break;
      }
    }
  }

  // Process DoH DMARC
  if (dmarcDohRes.status === "fulfilled" && dmarcDohRes.value?.Answer) {
    available = true;
    for (const ans of dmarcDohRes.value.Answer as Array<{ data?: string }>) {
      if (ans.data && ans.data.includes("v=DMARC1")) {
        hasDmarc = true;
        const match = ans.data.match(/p=([a-zA-Z]+)/);
        dmarcPolicy = match ? match[1]!.toLowerCase() : "none";
        break;
      }
    }
  }

  // Check email spoofing posture if domain has MX records (email server active)
  if (available && mxRecords.length > 0 && !hasSpf && !hasDmarc) {
    findings.push({
      id: "dns:missing-email-auth",
      category: "dns",
      severity: "low",
      confidence: "high",
      title: "Missing SPF and DMARC email authentication records",
      explanation:
        "The domain publishes active mail exchange (MX) records but lacks SPF and DMARC protection. This allows attackers to forge sender addresses from this domain in email phishing campaigns.",
      evidence: [`Domain: ${cleanDomain}`, "SPF: Missing", "DMARC: Missing"],
      remediation: "Verify any unsolicited emails purporting to originate from this domain through alternate channels.",
      source: "observed",
      penalty: PENALTIES.missingSpfAndDmarc,
    });
  }

  return {
    available,
    domain: cleanDomain,
    domainAgeDays,
    registrationDate,
    expiryDate,
    registrar,
    ctCertAgeDays,
    ctCertTotal,
    ctIssuers,
    hasSpf,
    hasDmarc,
    dmarcPolicy,
    mxRecords,
    aRecords,
    findings,
    limitations,
    error: available ? null : (rdapError ?? "Domain intelligence lookups could not be completed."),
  };
}
