import { describe, expect, it } from "vitest";
import { analyzeDomainIntel } from "../../src/security/domain-intel";

describe("Sentinel Domain Intelligence Analyzer", () => {
  it("processes RDAP registration data and identifies young domains", async () => {
    const fixedNow = new Date("2026-03-01T00:00:00Z").getTime();
    const regDate = "2026-02-20T00:00:00Z"; // 9 days old

    const mockFetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.includes("rdap.org")) {
        return new Response(
          JSON.stringify({
            events: [{ eventAction: "registration", eventDate: regDate }],
            entities: [
              {
                roles: ["registrar"],
                vcardArray: ["vcard", [["fn", {}, "text", "Example Registrar LLC"]]],
              },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (urlStr.includes("crt.sh")) {
        return new Response(
          JSON.stringify([
            {
              entry_timestamp: "2026-02-20T01:00:00",
              issuer_name: "C=US, O=Let's Encrypt, CN=R3",
            },
          ]),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (urlStr.includes("cloudflare-dns.com")) {
        if (urlStr.includes("type=TXT") && !urlStr.includes("_dmarc")) {
          // SPF record
          return new Response(
            JSON.stringify({
              Status: 0,
              Answer: [{ data: '"v=spf1 include:_spf.google.com ~all"' }],
            }),
            { status: 200 },
          );
        }
        if (urlStr.includes("_dmarc")) {
          // DMARC record
          return new Response(
            JSON.stringify({
              Status: 0,
              Answer: [{ data: '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"' }],
            }),
            { status: 200 },
          );
        }
        return new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
      }
      return new Response(null, { status: 404 });
    };

    const result = await analyzeDomainIntel("newly-created.example", {
      now: fixedNow,
      fetchFn: mockFetch as unknown as typeof fetch,
    });

    expect(result.available).toBe(true);
    expect(result.domainAgeDays).toBe(9);
    expect(result.registrar).toBe("Example Registrar LLC");
    expect(result.hasSpf).toBe(true);
    expect(result.hasDmarc).toBe(true);
    expect(result.dmarcPolicy).toBe("reject");
    expect(result.ctCertAgeDays).toBe(9);

    // Finding for domain < 14 days old must be triggered with high severity
    const youngFinding = result.findings.find((f) => f.id === "domain:very-young");
    expect(youngFinding).toBeDefined();
    expect(youngFinding?.severity).toBe("high");
    expect(youngFinding?.penalty).toBeGreaterThan(0);
  });

  it("handles DNS DoH failure or missing SPF/DMARC without false fraud verdict", async () => {
    const fixedNow = new Date("2026-03-01T00:00:00Z").getTime();
    const regDate = "2020-01-01T00:00:00Z"; // ~6 years old domain

    const mockFetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.includes("rdap.org")) {
        return new Response(
          JSON.stringify({
            events: [{ eventAction: "registration", eventDate: regDate }],
          }),
          { status: 200 },
        );
      }
      if (urlStr.includes("type=MX")) {
        return new Response(JSON.stringify({ Status: 0, Answer: [{ data: "10 mail.established.example" }] }), { status: 200 });
      }
      // DNS returns empty for SPF and DMARC
      return new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
    };

    const result = await analyzeDomainIntel("established.example", {
      now: fixedNow,
      fetchFn: mockFetch as unknown as typeof fetch,
    });

    expect(result.available).toBe(true);
    expect(result.hasSpf).toBe(false);
    expect(result.hasDmarc).toBe(false);
    expect(result.mxRecords.length).toBe(1);
    // Missing SPF/DMARC finding generated as low severity, never marking site as dangerous
    const dnsFinding = result.findings.find((f) => f.id === "dns:missing-email-auth");
    expect(dnsFinding).toBeDefined();
    expect(dnsFinding?.severity).toBe("low");
  });

  it("handles total network outage gracefully (unavailable check != unsafe site)", async () => {
    const mockFetch = async () => {
      throw new Error("DNS resolution failure");
    };

    const result = await analyzeDomainIntel("offline.example", {
      fetchFn: mockFetch as unknown as typeof fetch,
    });

    expect(result.available).toBe(false);
    expect(result.findings).toEqual([]);
    expect(result.limitations.some((l) => l.includes("never treated as proof of safety or guilt"))).toBe(true);
  });
});
