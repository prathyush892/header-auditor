import { describe, expect, it } from "vitest";
import { makeFinding, Status } from "../src/index.js";

describe("makeFinding", () => {
  it("fills defaults and freezes the result", () => {
    const f = makeFinding({ check: "X", status: Status.Info, detail: "d" });
    expect(f).toEqual({
      check: "X",
      status: "info",
      detail: "d",
      weight: 0,
      score: 0,
      recommendation: "",
    });
    expect(Object.isFrozen(f)).toBe(true);
  });

  it("serialises to the same JSON keys as the Python Finding", () => {
    const f = makeFinding({ check: "X", status: Status.Pass, detail: "d", weight: 5, score: 5 });
    expect(Object.keys(JSON.parse(JSON.stringify(f)) as object).sort()).toEqual(
      ["check", "detail", "recommendation", "score", "status", "weight"].sort(),
    );
  });

  it.each([
    { weight: -1, score: 0 },
    { weight: 1.5, score: 0 },
    { weight: 10, score: 11 },
    { weight: 10, score: -1 },
    { weight: 10, score: 2.5 },
    { weight: 0, score: 1 },
  ])("rejects an invalid score/weight pair %o", ({ weight, score }) => {
    expect(() =>
      makeFinding({ check: "X", status: Status.Warn, detail: "", weight, score }),
    ).toThrow(RangeError);
  });
});
