import { describe, expect, it } from "vitest";

import {
  DEFAULT_API_INTERNAL_URL,
  parseApiInternalUrl,
  SECURITY_HEADERS,
  WebConfigError,
} from "@/lib/server-config";

describe("parseApiInternalUrl", () => {
  it("defaults to the local API", () => {
    expect(parseApiInternalUrl(undefined)).toBe(DEFAULT_API_INTERNAL_URL);
    expect(parseApiInternalUrl("  ")).toBe(DEFAULT_API_INTERNAL_URL);
  });

  it("accepts an origin, with or without a trailing slash", () => {
    expect(parseApiInternalUrl("http://api:3001")).toBe("http://api:3001");
    expect(parseApiInternalUrl("https://api.internal/")).toBe("https://api.internal");
  });

  it.each([
    ["not a URL", "api:3001:x"],
    ["relative", "/api"],
    ["another scheme", "file:///etc/passwd"],
    ["credentials", "http://user:pass@api:3001"],
    ["a path", "http://api:3001/v1"],
    ["a query", "http://api:3001?x=1"],
    ["a fragment", "http://api:3001#x"],
  ])("rejects %s", (_label, value) => {
    expect(() => parseApiInternalUrl(value)).toThrow(WebConfigError);
  });
});

describe("SECURITY_HEADERS", () => {
  const byName = new Map(SECURITY_HEADERS.map((h) => [h.key.toLowerCase(), h.value]));

  it("forbids framing two ways (old and new browsers)", () => {
    expect(byName.get("x-frame-options")).toBe("DENY");
    expect(byName.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });

  it("sets nosniff and a referrer policy", () => {
    expect(byName.get("x-content-type-options")).toBe("nosniff");
    expect(byName.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
  });
});
