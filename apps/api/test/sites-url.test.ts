import { describe, expect, it } from "vitest";

import { isDnsHostname, normalizeHostname, normalizeSiteUrl } from "../src/sites/url.js";

function ok(input: string, allowPrivateTargets = false): string {
  const result = normalizeSiteUrl(input, { allowPrivateTargets });
  if (!result.ok) throw new Error(`expected ${input} to be valid, got: ${result.reason}`);
  return result.value;
}

function reason(input: string, allowPrivateTargets = false): string {
  const result = normalizeSiteUrl(input, { allowPrivateTargets });
  if (result.ok) throw new Error(`expected ${input} to be rejected, got ${result.value}`);
  return result.reason;
}

describe("normalizeSiteUrl", () => {
  it.each([
    ["https://example.com", "https://example.com"],
    ["https://example.com/", "https://example.com"],
    ["HTTPS://Example.COM", "https://example.com"],
    ["example.com", "https://example.com"],
    ["  example.com  ", "https://example.com"],
    ["https://example.com.", "https://example.com"],
    ["https://example.com:443", "https://example.com"],
    ["http://example.com:80/", "http://example.com"],
    ["https://example.com:8443", "https://example.com:8443"],
    ["example.com:8443", "https://example.com:8443"],
    ["https://sub.domain.example.co.uk", "https://sub.domain.example.co.uk"],
    ["https://bücher.example", "https://xn--bcher-kva.example"],
  ])("normalises %j to %j", (input, expected) => {
    // .example is reserved, so the IDN case needs the private flag; the rest don't.
    expect(ok(input, input.includes("bücher"))).toBe(expected);
  });

  it("collapses every spelling of an origin to one value", () => {
    const spellings = ["example.com", "https://EXAMPLE.com/", "https://example.com.:443"];
    expect(new Set(spellings.map((s) => ok(s)))).toEqual(new Set(["https://example.com"]));
  });

  it("converts unicode hostnames to punycode", () => {
    expect(ok("https://münchen.de")).toBe("https://xn--mnchen-3ya.de");
  });

  it.each([
    ["", "is required"],
    ["   ", "is required"],
    ["ftp://example.com", "must use http or https"],
    ["javascript:alert(1)", "must be a valid URL"],
    ["file:///etc/passwd", "must use http or https"],
    ["https://user:pw@example.com", "must not contain credentials"],
    ["https://user@example.com", "must not contain credentials"],
    ["https://example.com/login", "must be an origin"],
    ["https://example.com/?a=1", "must be an origin"],
    ["https://example.com?", "must be an origin"],
    ["https://example.com#top", "must be an origin"],
    ["https://exa mple.com", "must not contain spaces"],
    ["https://exa\nmple.com", "must not contain spaces"],
    ["https://example.com\u0000", "must not contain spaces"],
    ["https://", "must be a valid URL"],
    ["https://-bad-.com", "invalid hostname"],
    ["https://exa_mple.com", "invalid hostname"],
    ["https://example", "fully qualified"],
    // WHATWG URL treats a numeric last label as IPv4 and fails to parse it.
    ["https://example.123", "must be a valid URL"],
  ])("rejects %j (%s)", (input, expected) => {
    expect(reason(input)).toContain(expected);
  });

  it("rejects over-long input", () => {
    expect(reason(`https://${"a".repeat(2_100)}.com`)).toBe("is too long");
  });

  it("rejects hostnames with labels over 63 characters", () => {
    expect(reason(`https://${"a".repeat(64)}.com`)).toContain("invalid hostname");
  });

  describe("private targets (SSRF pre-filter)", () => {
    it.each([
      "http://127.0.0.1",
      "http://127.0.0.1:8080",
      "http://10.0.0.1",
      "http://169.254.169.254",
      "http://[::1]",
      "http://[fd00::1]",
      "http://0x7f.0.0.1",
      "http://2130706433",
      "http://017700000001",
      "http://8.8.8.8",
    ])("refuses IP literal %j", (input) => {
      expect(reason(input)).toBe("must use a domain name, not an IP address");
    });

    it.each([
      "http://localhost",
      "http://localhost:3000",
      "http://app.localhost",
      "http://printer.local",
      "http://db.internal",
      "http://router.home.arpa",
      "http://x.invalid",
      "http://site.test",
      "http://abc.onion",
      "http://LOCALHOST.",
    ])("refuses special-use name %j", (input) => {
      expect(reason(input)).toMatch(/public domain name|fully qualified/);
    });

    it("does not treat look-alike public names as reserved", () => {
      expect(ok("https://notlocalhost.com")).toBe("https://notlocalhost.com");
      expect(ok("https://local.example.org")).toBe("https://local.example.org");
      expect(ok("https://internal.dev")).toBe("https://internal.dev");
    });

    it("accepts IPs and localhost when private targets are allowed (dev and e2e)", () => {
      expect(ok("http://127.0.0.1:4010", true)).toBe("http://127.0.0.1:4010");
      expect(ok("http://[::1]:4010/", true)).toBe("http://[::1]:4010");
      expect(ok("http://localhost:3000", true)).toBe("http://localhost:3000");
      expect(ok("http://mock.test", true)).toBe("http://mock.test");
    });

    it("still validates everything else when private targets are allowed", () => {
      expect(reason("http://127.0.0.1/path", true)).toContain("must be an origin");
      expect(reason("ftp://127.0.0.1", true)).toBe("must use http or https");
    });
  });
});

describe("normalizeHostname", () => {
  it.each([
    ["cdn.example.com", "cdn.example.com"],
    ["  CDN.Example.COM  ", "cdn.example.com"],
    ["static.example.com.", "static.example.com"],
    ["bücher.de", "xn--bcher-kva.de"],
  ])("normalises %j to %j", (input, expected) => {
    expect(normalizeHostname(input)).toEqual({ ok: true, value: expected });
  });

  it.each([
    "",
    "https://cdn.example.com",
    "cdn.example.com/path",
    "cdn.example.com:443",
    "*.example.com",
    "cdn",
    "127.0.0.1",
    "exa mple.com",
    "-bad.com",
    "a".repeat(254),
  ])("rejects %j", (input) => {
    expect(normalizeHostname(input).ok).toBe(false);
  });
});

describe("isDnsHostname", () => {
  it("accepts LDH names and rejects the rest", () => {
    expect(isDnsHostname("a-b.example.com")).toBe(true);
    expect(isDnsHostname("xn--bcher-kva.de")).toBe(true);
    expect(isDnsHostname("")).toBe(false);
    expect(isDnsHostname("a..b")).toBe(false);
    expect(isDnsHostname("a_b.com")).toBe(false);
    expect(isDnsHostname("a-.com")).toBe(false);
  });
});
