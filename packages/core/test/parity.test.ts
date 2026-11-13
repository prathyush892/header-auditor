/**
 * Runs the shared cross-engine cases in spec/parity/. The Python CLI runs the
 * same files (cli-python/tests/test_parity.py), so a behaviour change in either
 * engine that isn't mirrored in the other fails CI.
 */
import { describe, expect, it } from "vitest";
import spec from "../../../spec/parity/checks.json" with { type: "json" };
import scoring from "../../../spec/parity/scoring.json" with { type: "json" };
import {
  buildReport,
  checkContentTypeOptions,
  checkCookies,
  checkCoop,
  checkCsp,
  checkFraming,
  checkHsts,
  checkInfoDisclosure,
  checkPermissionsPolicy,
  checkReferrerPolicy,
  HeaderMap,
  makeFinding,
  runAll,
  scoreFindings,
  Status,
  type Finding,
} from "../src/index.js";

type CheckRunner = (headers: HeaderMap, isHttps: boolean) => Finding;

const RUNNERS: Readonly<Record<string, CheckRunner>> = {
  hsts: (h, isHttps) => checkHsts(h, { isHttps }),
  "content-type-options": (h) => checkContentTypeOptions(h),
  "referrer-policy": (h) => checkReferrerPolicy(h),
  csp: (h) => checkCsp(h),
  framing: (h) => checkFraming(h),
  "permissions-policy": (h) => checkPermissionsPolicy(h),
  coop: (h) => checkCoop(h),
  "info-disclosure": (h) => checkInfoDisclosure(h),
  cookies: (h, isHttps) => checkCookies(h, { isHttps }),
};

interface ParityCase {
  check: string;
  name: string;
  headers: string[][];
  isHttps?: boolean;
  expect: { status: string; score: number; weight: number };
}

const toHeaderMap = (headers: string[][]) =>
  new HeaderMap(headers.map(([name = "", value = ""]) => [name, value] as const));

const cases = spec.cases as ParityCase[];

describe("cross-engine parity (spec/parity/checks.json)", () => {
  it("uses a known spec version", () => {
    expect(spec.version).toBe(1);
  });

  it("has cases for every check and a runner for every case", () => {
    expect(new Set(cases.map((c) => c.check))).toEqual(new Set(Object.keys(RUNNERS)));
  });

  it.each(cases.map((c) => [`${c.check}: ${c.name}`, c] as const))("%s", (_label, c) => {
    const run = RUNNERS[c.check];
    if (!run) throw new Error(`No runner for check "${c.check}"`);
    const f = run(toHeaderMap(c.headers), c.isHttps ?? true);
    expect({ status: f.status, score: f.score, weight: f.weight }).toEqual(c.expect);
  });
});

describe("cross-engine parity (spec/parity/scoring.json)", () => {
  it("uses a known spec version", () => {
    expect(scoring.version).toBe(1);
  });

  it.each(scoring.points.map((c) => [c.name, c] as const))("points: %s", (_label, c) => {
    const findings = c.findings.map(({ score, weight }) =>
      makeFinding({ check: "c", status: Status.Pass, detail: "", score, weight }),
    );
    const { score, grade } = scoreFindings(findings);
    expect({ score, grade }).toEqual(c.expect);
  });

  it.each(scoring.reports.map((c) => [c.name, c] as const))("report: %s", (_label, c) => {
    const report = buildReport(
      "https://x",
      200,
      runAll(toHeaderMap(c.headers), { isHttps: c.isHttps }),
    );
    expect({
      score: report.score,
      grade: report.grade,
      maxScore: report.maxScore,
      statuses: report.findings.map((f) => f.status),
    }).toEqual(c.expect);
  });
});
