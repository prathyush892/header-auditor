/**
 * Unit tests for the new checks (Permissions-Policy, COOP, info disclosure,
 * cookies) and for scoring/grading. Mirrors cli-python/tests/test_checks.py;
 * the shared status/score tables run in parity.test.ts.
 */
import { describe, expect, it } from "vitest";
import {
  buildReport,
  checkCookies,
  checkCoop,
  checkInfoDisclosure,
  checkPermissionsPolicy,
  coopToken,
  gradeFor,
  HeaderMap,
  leakedHeaders,
  makeFinding,
  missingCookieFlags,
  parseSetCookie,
  reportToJson,
  roundHalfEven,
  runAll,
  scoreFindings,
  Status,
} from "../src/index.js";

const H = (record: Record<string, string | string[]> = {}) => new HeaderMap(record);

describe("checkPermissionsPolicy", () => {
  it("passes when present and warns with a recommendation when missing", () => {
    expect(checkPermissionsPolicy(H({ "Permissions-Policy": "camera=()" }))).toMatchObject({
      status: Status.Pass,
      detail: "Present.",
      score: 10,
    });
    expect(checkPermissionsPolicy(H())).toMatchObject({
      status: Status.Warn,
      score: 0,
      recommendation: "Add e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
    });
  });
});

describe("checkCoop", () => {
  it("extracts the token and drops structured-header parameters", () => {
    expect(coopToken('same-origin; report-to="coop"')).toBe("same-origin");
    expect(coopToken("  SAME-ORIGIN-ALLOW-POPUPS ")).toBe("same-origin-allow-popups");
    expect(coopToken("")).toBe("");
  });

  it("shows the normalised token in the detail", () => {
    const f = checkCoop(H({ "Cross-Origin-Opener-Policy": 'Same-Origin; report-to="c"' }));
    expect(f).toMatchObject({ status: Status.Pass, detail: "same-origin.", score: 5 });
  });

  it("treats unsafe-none and unknown tokens as permissive", () => {
    for (const value of ["unsafe-none", "same-origin-plus-coep", "same-origin,same-origin"]) {
      expect(checkCoop(H({ "Cross-Origin-Opener-Policy": value })).status).toBe(Status.Warn);
    }
  });
});

describe("checkInfoDisclosure", () => {
  it("mirrors the Python test_info_leak cases", () => {
    expect(checkInfoDisclosure(H({ Server: "nginx" })).status).toBe(Status.Pass);
    const leak = checkInfoDisclosure(H({ Server: "Apache/2.4.1", "X-Powered-By": "PHP/8.1" }));
    expect(leak).toMatchObject({
      status: Status.Warn,
      detail: "Exposes Server: Apache/2.4.1, X-Powered-By: PHP/8.1.",
      recommendation: "Remove version details from these headers.",
    });
  });

  it("reports leaks in a fixed order regardless of header order", () => {
    const h = new HeaderMap([
      ["x-aspnetmvc-version", "5.2"],
      ["X-Powered-By", "ASP.NET"],
      ["server", "Microsoft-IIS/10.0"],
    ]);
    expect(leakedHeaders(h)).toEqual([
      "Server: Microsoft-IIS/10.0",
      "X-Powered-By: ASP.NET",
      "X-AspNetMvc-Version: 5.2",
    ]);
  });
});

describe("parseSetCookie", () => {
  it("splits the name-value pair from trimmed, lowercased attribute names", () => {
    const c = parseSetCookie(" sid = abc=def; Path=/; Secure ; SameSite = Lax; HTTPONLY");
    expect(c.name).toBe("sid");
    expect([...c.attributes]).toEqual(["path", "secure", "samesite", "httponly"]);
  });

  it("handles a cookie with no attributes or no '='", () => {
    expect(parseSetCookie("tok")).toEqual({ name: "tok", attributes: new Set() });
    expect(parseSetCookie("").name).toBe("");
  });

  it("does not treat a flag name inside the cookie value as an attribute", () => {
    const c = parseSetCookie("pref=Secure");
    expect(missingCookieFlags(c)).toEqual(["Secure", "HttpOnly", "SameSite"]);
  });

  it("only requires Secure over HTTPS", () => {
    const c = parseSetCookie("sid=1; HttpOnly; SameSite=Strict");
    expect(missingCookieFlags(c, { isHttps: false })).toEqual([]);
    expect(missingCookieFlags(c, { isHttps: true })).toEqual(["Secure"]);
  });
});

describe("checkCookies", () => {
  it("mirrors the Python test_cookies cases", () => {
    expect(checkCookies(H()).status).toBe(Status.Info);
    expect(checkCookies(H({ "Set-Cookie": "sid=1; Secure; HttpOnly; SameSite=Lax" })).status).toBe(
      Status.Pass,
    );
    const bad = checkCookies(H({ "Set-Cookie": "sid=1; Path=/" }));
    expect(bad.status).toBe(Status.Warn);
    expect(bad.detail).toContain("Secure/HttpOnly/SameSite");
    const http = checkCookies(H({ "Set-Cookie": "sid=1; HttpOnly; SameSite=Lax" }), {
      isHttps: false,
    });
    expect(http.status).toBe(Status.Pass);
  });

  it("lists every offending cookie and keeps cookies separate (dates contain commas)", () => {
    const f = checkCookies(
      H({
        "Set-Cookie": [
          "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
          "b=2; Secure; HttpOnly; SameSite=Lax",
          "c=3; Secure",
        ],
      }),
    );
    expect(f).toMatchObject({
      status: Status.Warn,
      detail: "a missing Secure/HttpOnly/SameSite; c missing HttpOnly/SameSite.",
      score: 4,
    });
  });

  it("counts cookies in the pass detail", () => {
    const ok = "x=1; Secure; HttpOnly; SameSite=Lax";
    expect(checkCookies(H({ "Set-Cookie": [ok, ok] })).detail).toBe(
      "All 2 cookie(s) have Secure/HttpOnly/SameSite.",
    );
  });
});

describe("roundHalfEven", () => {
  it("rounds ties to the even neighbour like Python's round()", () => {
    expect(roundHalfEven(5, 2)).toBe(2); // 2.5
    expect(roundHalfEven(7, 2)).toBe(4); // 3.5
    expect(roundHalfEven(1, 2)).toBe(0); // 0.5
    expect(roundHalfEven(250, 100)).toBe(2);
  });

  it("rounds non-ties to the nearest integer", () => {
    expect(roundHalfEven(2, 3)).toBe(1);
    expect(roundHalfEven(1, 3)).toBe(0);
    expect(roundHalfEven(200, 3)).toBe(67);
    expect(roundHalfEven(0, 7)).toBe(0);
  });

  it("rejects inputs it cannot round exactly", () => {
    expect(() => roundHalfEven(1, 0)).toThrow(RangeError);
    expect(() => roundHalfEven(-1, 2)).toThrow(RangeError);
    expect(() => roundHalfEven(1.5, 2)).toThrow(RangeError);
    expect(() => roundHalfEven(Number.MAX_SAFE_INTEGER + 1, 2)).toThrow(RangeError);
  });
});

describe("scoring", () => {
  it("maps scores to grades at the documented cutoffs", () => {
    expect([100, 90, 89, 75, 74, 60, 59, 40, 39, 0].map(gradeFor)).toEqual([
      "A",
      "A",
      "B",
      "B",
      "C",
      "C",
      "D",
      "D",
      "F",
      "F",
    ]);
  });

  it("returns score 0 and grade F when nothing was graded", () => {
    expect(scoreFindings([])).toEqual({ earned: 0, maxScore: 0, score: 0, grade: "F" });
  });

  it("mirrors the Python test_report_scoring cases", () => {
    expect(buildReport("http://x", 200, runAll(H(), { isHttps: true })).grade).toBe("F");
    const strong = H({
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Permissions-Policy": "camera=()",
      "Cross-Origin-Opener-Policy": "same-origin",
    });
    const r = buildReport("https://x", 200, runAll(strong, { isHttps: true }));
    expect(r).toMatchObject({ score: 100, grade: "A", maxScore: 100, earned: 100 });
    expect(r.findings).toHaveLength(9);
  });

  it("serialises to the same JSON shape as the Python CLI", () => {
    const r = buildReport("https://x", 404, [
      makeFinding({ check: "c", status: Status.Warn, detail: "d", weight: 4, score: 1 }),
    ]);
    expect(reportToJson(r)).toEqual({
      url: "https://x",
      status_code: 404,
      score: 25,
      grade: "F",
      findings: [
        { check: "c", status: "warn", detail: "d", weight: 4, score: 1, recommendation: "" },
      ],
    });
  });

  it("freezes the report and rejects invalid status codes", () => {
    const r = buildReport("https://x", 200, []);
    expect(Object.isFrozen(r)).toBe(true);
    expect(Object.isFrozen(r.findings)).toBe(true);
    for (const bad of [0, 99, 600, 200.5, Number.NaN]) {
      expect(() => buildReport("https://x", bad, [])).toThrow(RangeError);
    }
  });
});
