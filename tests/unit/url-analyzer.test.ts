import { describe, expect, it } from "vitest";
import { analyzeUrl } from "../../src/security/url-analyzer";

describe("Sentinel URL analyzer", () => {
  it("removes credential-bearing query data from normalized URLs", () => {
    const result = analyzeUrl("https://example.com/login?token=secret#fragment");
    expect(result.normalizedUrl).toBe("https://example.com/login");
    expect(result.hostname).toBe("example.com");
    expect(result.hasEmbeddedCredentials).toBe(false);
  });

  it("detects punycode and login context without declaring a verdict", () => {
    const result = analyzeUrl("https://xn--pple-43d.example/login");
    expect(result.isPunycode).toBe(true);
    expect(result.hasLoginTerm).toBe(true);
    expect(result.indicators.length).toBeGreaterThan(0);
  });

  it("does not treat HTTPS as a phishing verdict", () => {
    const result = analyzeUrl("https://www.example.com/");
    expect(result.protocol).toBe("https:");
    expect(result.brandImpersonation).toEqual([]);
  });

  it("detects '@' symbol in URL authority as credential confusion", () => {
    const result = analyzeUrl("https://paypal.com@malicious-host.net/login");
    expect(result.hasAtSymbol).toBe(true);
    expect(result.indicators.some((i) => i.includes("at-symbol"))).toBe(true);
  });

  it("detects double-slash redirect in path", () => {
    const result = analyzeUrl("https://example.com//phishing-redirect");
    expect(result.hasDoubleSlashRedirect).toBe(true);
    expect(result.indicators.some((i) => i.includes("double-slash"))).toBe(true);
  });

  it("detects non-standard network ports", () => {
    const standard = analyzeUrl("https://example.com/test");
    const nonStandard = analyzeUrl("https://example.com:8443/test");
    expect(standard.hasNonStandardPort).toBe(false);
    expect(nonStandard.hasNonStandardPort).toBe(true);
    expect(nonStandard.indicators.some((i) => i.includes("non-standard-port"))).toBe(true);
  });

  it("detects deceptive 'https' token in domain name", () => {
    const deceptive = analyzeUrl("https://https-secure-bank-login.com/");
    expect(deceptive.hasHttpsInHostname).toBe(true);
    expect(deceptive.indicators.some((i) => i.includes("https"))).toBe(true);
  });

  it("detects IP-address-based hosts", () => {
    const ipUrl = analyzeUrl("http://192.168.1.1/admin");
    expect(ipUrl.isIpAddress).toBe(true);
    expect(ipUrl.hostname).toBe("192.168.1.1");
  });
});
