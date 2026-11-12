/**
 * Unit tests for the CSP parser and the CSP / clickjacking checks. The shared
 * status/score table for both checks lives in spec/parity/checks.json.
 */
import { describe, expect, it } from "vitest";
import {
  checkCsp,
  checkFraming,
  cspProblems,
  effectiveScriptSources,
  findAnyOriginSource,
  hasSource,
  hasSourcePrefix,
  HeaderMap,
  neutralizesUnsafeInline,
  parseCsp,
  Status,
} from "../src/index.js";

const H = (record: Record<string, string> = {}) => new HeaderMap(record);
const CSP = "Content-Security-Policy";

describe("parseCsp", () => {
  it("splits directives and source tokens", () => {
    const policy = parseCsp("default-src 'self'; img-src 'self' https://cdn.test");
    expect([...policy.keys()]).toEqual(["default-src", "img-src"]);
    expect(policy.get("img-src")).toEqual(["'self'", "https://cdn.test"]);
  });

  it("lowercases directive names but keeps source tokens as sent", () => {
    const policy = parseCsp("Script-SRC 'Nonce-AbC'");
    expect(policy.get("script-src")).toEqual(["'Nonce-AbC'"]);
  });

  it("treats every kind of ASCII whitespace as a separator", () => {
    const policy = parseCsp("\tdefault-src\t'self'\n  'unsafe-inline'\f;\r\nobject-src  'none'  ");
    expect(policy.get("default-src")).toEqual(["'self'", "'unsafe-inline'"]);
    expect(policy.get("object-src")).toEqual(["'none'"]);
  });

  it("skips empty directives and keeps directives with no sources", () => {
    const policy = parseCsp(";; ;frame-ancestors;upgrade-insecure-requests;");
    expect(policy.get("frame-ancestors")).toEqual([]);
    expect(policy.has("upgrade-insecure-requests")).toBe(true);
    expect(policy.size).toBe(2);
  });

  it("ignores duplicate directives (first wins, like browsers)", () => {
    expect(parseCsp("script-src 'self'; script-src *").get("script-src")).toEqual(["'self'"]);
    expect(parseCsp("script-src 'self'; SCRIPT-SRC *").get("script-src")).toEqual(["'self'"]);
  });

  it("ignores directives with invalid names", () => {
    const policy = parseCsp("scr!pt-src *; script_src *; 'self'; default-src 'none'");
    expect([...policy.keys()]).toEqual(["default-src"]);
  });

  it("returns an empty, frozen-value policy for empty input", () => {
    expect(parseCsp("").size).toBe(0);
    expect(parseCsp("   ").size).toBe(0);
    expect(Object.isFrozen(parseCsp("a-src x").get("a-src"))).toBe(true);
  });

  it("parses large inputs in linear time", () => {
    const big = Array.from({ length: 5_000 }, (_, i) => `x${String(i)}-src a b c`).join("; ");
    const started = performance.now();
    expect(parseCsp(big).size).toBe(5_000);
    expect(performance.now() - started).toBeLessThan(1_000);
  });
});

describe("source helpers", () => {
  it("compares keywords case-insensitively", () => {
    expect(hasSource(["'SELF'"], "'self'")).toBe(true);
    expect(hasSource(["self"], "'self'")).toBe(false);
    expect(hasSourcePrefix(["'NONCE-x'"], "'nonce-")).toBe(true);
  });

  it("finds sources that match any origin", () => {
    expect(findAnyOriginSource(["'self'", "*"])).toBe("*");
    expect(findAnyOriginSource(["HTTPS:"])).toBe("HTTPS:");
    expect(findAnyOriginSource(["http:"])).toBe("http:");
    expect(findAnyOriginSource(["https://*"])).toBe("https://*");
    expect(findAnyOriginSource(["https://*.example.test", "'self'", "data:"])).toBeUndefined();
    expect(findAnyOriginSource(["https://a.test"])).toBeUndefined();
  });

  it("falls back from script-src to default-src", () => {
    expect(effectiveScriptSources(parseCsp("default-src 'self'"))).toEqual(["'self'"]);
    expect(effectiveScriptSources(parseCsp("default-src *; script-src 'none'"))).toEqual([
      "'none'",
    ]);
    expect(effectiveScriptSources(parseCsp("img-src *"))).toBeUndefined();
  });

  it("knows which sources neutralize 'unsafe-inline'", () => {
    expect(neutralizesUnsafeInline(["'nonce-abc'"])).toBe(true);
    expect(neutralizesUnsafeInline(["'sha256-abc='"])).toBe(true);
    expect(neutralizesUnsafeInline(["'SHA512-abc='"])).toBe(true);
    expect(neutralizesUnsafeInline(["'strict-dynamic'"])).toBe(true);
    expect(neutralizesUnsafeInline(["'sha1-abc='", "'self'"])).toBe(false);
  });
});

describe("checkCsp", () => {
  it("mirrors the Python test_csp cases", () => {
    expect(checkCsp(H()).status).toBe(Status.Fail);
    expect(
      checkCsp(H({ "Content-Security-Policy-Report-Only": "default-src 'self'" })).status,
    ).toBe(Status.Warn);
    const good = "default-src 'self'; object-src 'none'; frame-ancestors 'none'";
    expect(checkCsp(H({ [CSP]: good })).status).toBe(Status.Pass);
    const weak = checkCsp(H({ [CSP]: "script-src * 'unsafe-inline' 'unsafe-eval'" }));
    expect(weak.status).toBe(Status.Warn);
    expect(weak.detail).toContain("unsafe-inline");
    expect(weak.detail).toContain("any origin");
  });

  it("lists every problem in a stable order", () => {
    expect(cspProblems(parseCsp("script-src * 'unsafe-inline' 'unsafe-eval'"))).toEqual([
      "script-src allows 'unsafe-inline'",
      "script-src allows 'unsafe-eval'",
      "script-src allows any origin (*)",
      "object-src not restricted",
    ]);
    expect(cspProblems(parseCsp("img-src 'self'"))).toEqual([
      "no default-src or script-src",
      "object-src not restricted",
    ]);
  });

  it("produces the same detail and recommendation text as Python", () => {
    expect(checkCsp(H())).toMatchObject({
      check: CSP,
      detail: "Header missing.",
      recommendation:
        "Start with `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'`.",
    });
    expect(checkCsp(H({ [CSP]: "default-src 'self'" }))).toMatchObject({
      detail: "object-src not restricted.",
      score: 18,
      recommendation:
        "Tighten the policy: prefer nonces/hashes over 'unsafe-inline' and set object-src 'none'.",
    });
  });

  it("names the wildcard source it found", () => {
    const f = checkCsp(H({ [CSP]: "default-src 'none'; script-src https:" }));
    expect(f.detail).toBe("script-src allows any origin (https:).");
  });

  it("an enforced policy wins over a Report-Only one", () => {
    const f = checkCsp(
      H({
        [CSP]: "default-src 'none'",
        "Content-Security-Policy-Report-Only": "script-src *",
      }),
    );
    expect(f.status).toBe(Status.Pass);
  });

  it("never scores below the floor while a policy is present", () => {
    const f = checkCsp(H({ [CSP]: "script-src * 'unsafe-inline' 'unsafe-eval'" }));
    expect(f.score).toBe(5);
  });
});

describe("checkFraming", () => {
  it("mirrors the Python test_framing cases", () => {
    expect(checkFraming(H()).status).toBe(Status.Fail);
    expect(checkFraming(H({ "X-Frame-Options": "DENY" })).status).toBe(Status.Pass);
    expect(checkFraming(H({ "X-Frame-Options": "ALLOW-FROM x" })).status).toBe(Status.Warn);
    expect(checkFraming(H({ [CSP]: "frame-ancestors 'self'" })).status).toBe(Status.Pass);
    expect(checkFraming(H({ [CSP]: "frame-ancestors *" })).status).toBe(Status.Fail);
  });

  it("explains what it saw", () => {
    expect(checkFraming(H({ [CSP]: "frame-ancestors 'self'  https://a.test" })).detail).toBe(
      "CSP frame-ancestors 'self' https://a.test.",
    );
    expect(checkFraming(H({ [CSP]: "frame-ancestors" })).detail).toBe(
      "CSP frame-ancestors (empty, same as 'none').",
    );
    expect(checkFraming(H({ [CSP]: "frame-ancestors 'self' *" })).detail).toBe(
      "CSP frame-ancestors allows any origin (*).",
    );
    expect(checkFraming(H({ "X-Frame-Options": "sameorigin" })).detail).toBe(
      "X-Frame-Options: SAMEORIGIN.",
    );
  });

  it("lets frame-ancestors override X-Frame-Options", () => {
    const f = checkFraming(H({ [CSP]: "frame-ancestors https:", "X-Frame-Options": "DENY" }));
    expect(f.status).toBe(Status.Fail);
  });
});
