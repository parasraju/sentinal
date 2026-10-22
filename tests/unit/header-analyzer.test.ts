import { describe, expect, it } from "vitest";
import { analyzeSecurityHeaders } from "../../src/security/header-analyzer";

describe("Sentinel Security Header Analyzer", () => {
  it("audits presence of HSTS, CSP, and framing headers", async () => {
    const mockHeaders = new Headers({
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
      "content-security-policy": "default-src 'self'",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=()",
    });

    const mockFetch = async () => new Response(null, { status: 200, headers: mockHeaders });

    const result = await analyzeSecurityHeaders("https://example.com", {
      fetchFn: mockFetch as unknown as typeof fetch,
    });

    expect(result.available).toBe(true);
    expect(result.presentCount).toBe(6);
    expect(result.missingCount).toBe(0);
    expect(result.score).toBe(100);
    expect(result.findings.some((f) => f.id === "header:strong-posture")).toBe(true);
  });

  it("penalizes missing critical headers (HSTS and CSP) while avoiding false fraud claims", async () => {
    const mockHeaders = new Headers({
      "x-content-type-options": "nosniff",
    });

    const mockFetch = async () => new Response(null, { status: 200, headers: mockHeaders });

    const result = await analyzeSecurityHeaders("https://example.com", {
      fetchFn: mockFetch as unknown as typeof fetch,
    });

    expect(result.available).toBe(true);
    expect(result.presentCount).toBe(1);
    expect(result.missingCount).toBe(5);
    expect(result.findings.some((f) => f.id === "header:missing-critical-posture")).toBe(true);
    // Findings must have remediation and plain explanations
    const criticalFinding = result.findings.find((f) => f.id === "header:missing-critical-posture");
    expect(criticalFinding?.remediation).toBeDefined();
    expect(criticalFinding?.penalty).toBeGreaterThan(0);
  });

  it("gracefully falls back on network timeout or fetch error without throwing", async () => {
    const mockFetch = async () => {
      throw new Error("Connection timed out");
    };

    const result = await analyzeSecurityHeaders("https://unreachable.example", {
      fetchFn: mockFetch as unknown as typeof fetch,
    });

    expect(result.available).toBe(false);
    expect(result.error).toContain("timed out");
    expect(result.findings).toEqual([]);
    expect(result.limitations.length).toBeGreaterThan(0);
  });
});
