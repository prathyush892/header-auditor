/**
 * Runs the shared cross-engine cases in spec/parity/checks.json. The Python
 * CLI runs the same file (cli-python/tests/test_parity.py), so a behaviour
 * change in either engine that isn't mirrored in the other fails CI.
 */
import { describe, expect, it } from "vitest";
import spec from "../../../spec/parity/checks.json" with { type: "json" };
import {
  checkContentTypeOptions,
  checkHsts,
  checkReferrerPolicy,
  HeaderMap,
  type Finding,
} from "../src/index.js";

type CheckRunner = (headers: HeaderMap, isHttps: boolean) => Finding;

const RUNNERS: Readonly<Record<string, CheckRunner>> = {
  hsts: (h, isHttps) => checkHsts(h, { isHttps }),
  "content-type-options": (h) => checkContentTypeOptions(h),
  "referrer-policy": (h) => checkReferrerPolicy(h),
};

interface ParityCase {
  check: string;
  name: string;
  headers: string[][];
  isHttps?: boolean;
  expect: { status: string; score: number; weight: number };
}

const cases = spec.cases as ParityCase[];

describe("cross-engine parity (spec/parity/checks.json)", () => {
  it("uses a known spec version", () => {
    expect(spec.version).toBe(1);
  });

  it.each(cases.map((c) => [`${c.check}: ${c.name}`, c] as const))("%s", (_label, c) => {
    const run = RUNNERS[c.check];
    if (!run) throw new Error(`No runner for check "${c.check}"`);
    const entries = c.headers.map(([name = "", value = ""]) => [name, value] as const);
    const f = run(new HeaderMap(entries), c.isHttps ?? true);
    expect({ status: f.status, score: f.score, weight: f.weight }).toEqual(c.expect);
  });
});
