import { describe, expect, it } from "vitest";
import { buildAllowlistRules, computeEnabledRulesets, validateAllowlistRules } from "../../src/browser/network-rules";
import { DEFAULT_SETTINGS } from "../../src/shared/constants";

describe("Sentinel network rule validation", () => {
  it("accepts registrable domains and rejects malformed entries", () => {
    expect(validateAllowlistRules(["example.com", "https://login.example.com/path", "not a domain"]).valid).toEqual(["example.com"]);
    expect(validateAllowlistRules(["not a domain"]).rejected).toEqual(["not a domain"]);
  });

  it("uses conservative standard rules by default", () => {
    expect(computeEnabledRulesets(DEFAULT_SETTINGS)).toEqual(["analytics", "advertising", "social", "session_replay"]);
    expect(buildAllowlistRules(["example.com"])[0]?.condition.initiatorDomains).toEqual(["example.com"]);
  });
});
