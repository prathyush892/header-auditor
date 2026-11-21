import { describe, expect, it } from "vitest";

import {
  CHECK_NAME_MAX_LENGTH,
  type EngineFinding,
  findingRows,
  fromDbFindingStatus,
  stripNul,
  toDbFindingStatus,
  toDbGrade,
  toDbScore,
} from "../src/index.js";

function finding(overrides: Partial<EngineFinding> = {}): EngineFinding {
  return {
    check: "Strict-Transport-Security",
    status: "pass",
    detail: "max-age=31536000",
    weight: 15,
    score: 15,
    recommendation: "",
    ...overrides,
  };
}

describe("status and grade mapping", () => {
  it("round-trips every engine status", () => {
    for (const status of ["pass", "warn", "fail", "info"] as const) {
      expect(fromDbFindingStatus(toDbFindingStatus(status))).toBe(status);
    }
  });

  it.each(["PASS", "error", "", "__proto__", "toString"])("rejects unknown status %j", (status) => {
    expect(() => toDbFindingStatus(status)).toThrow(RangeError);
  });

  it("accepts the five engine grades", () => {
    expect(["A", "B", "C", "D", "F"].map(toDbGrade)).toEqual(["A", "B", "C", "D", "F"]);
  });

  it.each(["A+", "E", "a", ""])("rejects grade %j", (grade) => {
    expect(() => toDbGrade(grade)).toThrow(RangeError);
  });

  it.each([0, 57, 100])("accepts score %s", (score) => {
    expect(toDbScore(score)).toBe(score);
  });

  it.each([-1, 101, 99.5, Number.NaN])("rejects score %s", (score) => {
    expect(() => toDbScore(score)).toThrow(RangeError);
  });
});

describe("findingRows", () => {
  it("numbers positions across sections in order", () => {
    const rows = findingRows([
      [
        "HEADERS",
        [finding(), finding({ check: "Content-Security-Policy", status: "fail", score: 0 })],
      ],
      ["TLS", [finding({ check: "TLS protocol", weight: 10, score: 10 })]],
      ["DNS", []],
    ]);
    expect(rows.map((r) => [r.category, r.check, r.status, r.position])).toEqual([
      ["HEADERS", "Strict-Transport-Security", "PASS", 0],
      ["HEADERS", "Content-Security-Policy", "FAIL", 1],
      ["TLS", "TLS protocol", "PASS", 2],
    ]);
  });

  it("copies detail, weight, score and recommendation", () => {
    const [row] = findingRows([
      [
        "CONTENT",
        [finding({ status: "warn", score: 8, weight: 10, recommendation: "Add crossorigin" })],
      ],
    ]);
    expect(row).toMatchObject({ weight: 10, score: 8, recommendation: "Add crossorigin" });
  });

  it("strips NUL bytes that Postgres text columns reject", () => {
    const [row] = findingRows([
      [
        "HEADERS",
        [finding({ check: "Server\u0000", detail: "nginx\u0000/1.2", recommendation: "\u0000" })],
      ],
    ]);
    expect(row).toMatchObject({ check: "Server", detail: "nginx/1.2", recommendation: "" });
    expect(stripNul("a\u0000b\u0000")).toBe("ab");
  });

  it("rejects an unknown category", () => {
    expect(() => findingRows([["COOKIES" as "HEADERS", [finding()]]])).toThrow(/category/);
  });

  it.each([
    ["empty check name", { check: "  " }],
    ["over-long check name", { check: "x".repeat(CHECK_NAME_MAX_LENGTH + 1) }],
    ["negative weight", { weight: -1, score: 0 }],
    ["fractional weight", { weight: 1.5, score: 0 }],
    ["score above weight", { weight: 5, score: 6 }],
    ["negative score", { score: -1 }],
    ["unknown status", { status: "error" as EngineFinding["status"] }],
  ])("rejects a finding with %s", (_label, overrides) => {
    expect(() => findingRows([["HEADERS", [finding(overrides)]]])).toThrow(RangeError);
  });

  it("says which finding was invalid", () => {
    expect(() =>
      findingRows([["HEADERS", [finding(), finding({ check: "Referrer-Policy", score: 99 })]]]),
    ).toThrow(/Finding #1 \("Referrer-Policy"\)/);
  });
});
