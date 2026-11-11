/**
 * Unit tests mirroring cli-python/tests/test_checks.py (test_hsts and
 * test_simple_headers), plus TypeScript-specific edge cases. The shared
 * status/score table lives in spec/parity and runs in parity.test.ts.
 */
import { describe, expect, it } from "vitest";
import {
  checkContentTypeOptions,
  checkHsts,
  checkReferrerPolicy,
  effectiveReferrerPolicy,
  HeaderMap,
  parseMaxAge,
  Status,
} from "../src/index.js";

const H = (record: Record<string, string> = {}) => new HeaderMap(record);
const HSTS = "Strict-Transport-Security";

describe("checkHsts", () => {
  it("mirrors the Python test_hsts cases", () => {
    expect(checkHsts(H()).status).toBe(Status.Fail);
    expect(checkHsts(H({ [HSTS]: "max-age=100" })).status).toBe(Status.Warn);
    expect(checkHsts(H({ [HSTS]: "max-age=31536000" })).status).toBe(Status.Warn);
    expect(checkHsts(H({ [HSTS]: "max-age=31536000; includeSubDomains" })).status).toBe(
      Status.Pass,
    );
    expect(checkHsts(H(), { isHttps: false }).status).toBe(Status.Info);
  });

  it("produces the same detail and recommendation text as Python", () => {
    expect(checkHsts(H())).toMatchObject({
      check: HSTS,
      detail: "Header missing.",
      recommendation: "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    });
    expect(checkHsts(H({ [HSTS]: "max-age=100" })).detail).toBe(
      "max-age=100 is shorter than 6 months.",
    );
    expect(checkHsts(H({ [HSTS]: "max-age=0031536000" })).detail).toBe(
      "max-age=31536000 without includeSubDomains.",
    );
    expect(checkHsts(H({ [HSTS]: "preload" })).detail).toBe("No valid max-age in 'preload'.");
  });

  it("ignores HSTS sent over plain HTTP even when present", () => {
    const f = checkHsts(H({ [HSTS]: "max-age=31536000; includeSubDomains" }), { isHttps: false });
    expect(f).toMatchObject({ status: Status.Info, weight: 0, score: 0 });
  });

  it("parses max-age exactly, including values beyond Number.MAX_SAFE_INTEGER", () => {
    expect(parseMaxAge("max-age=31536000")).toBe(31_536_000n);
    expect(parseMaxAge('max-age="10"')).toBe(10n);
    expect(parseMaxAge("max-age=99999999999999999999")).toBe(99_999_999_999_999_999_999n);
    expect(parseMaxAge("max-age=abc")).toBeUndefined();
    expect(parseMaxAge("")).toBeUndefined();
  });
});

describe("checkContentTypeOptions", () => {
  it("mirrors the Python cases", () => {
    expect(checkContentTypeOptions(H({ "X-Content-Type-Options": "nosniff" })).status).toBe(
      Status.Pass,
    );
    expect(checkContentTypeOptions(H()).status).toBe(Status.Fail);
  });

  it("reports the unexpected value in lowercase like Python", () => {
    expect(checkContentTypeOptions(H({ "X-Content-Type-Options": "SNIFF" })).detail).toBe(
      "Unexpected value 'sniff'.",
    );
  });
});

describe("checkReferrerPolicy", () => {
  const RP = "Referrer-Policy";

  it("mirrors the Python cases", () => {
    expect(
      checkReferrerPolicy(H({ [RP]: "no-referrer, strict-origin-when-cross-origin" })).status,
    ).toBe(Status.Pass);
    expect(checkReferrerPolicy(H({ [RP]: "unsafe-url" })).status).toBe(Status.Fail);
    expect(checkReferrerPolicy(H()).status).toBe(Status.Warn);
  });

  it("grades the last (effective) token of a fallback list", () => {
    expect(effectiveReferrerPolicy("no-referrer, Unsafe-URL ")).toBe("unsafe-url");
    expect(effectiveReferrerPolicy(" , ,")).toBeUndefined();
    expect(checkReferrerPolicy(H({ [RP]: "origin" })).detail).toBe("'origin' can leak path data.");
  });
});
