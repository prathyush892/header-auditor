import { describe, expect, it } from "vitest";
import pkg from "../package.json" with { type: "json" };
import { ENGINE_NAME, ENGINE_VERSION } from "../src/index.js";

describe("@header-auditor/core scaffold", () => {
  it("identifies itself as the TypeScript engine", () => {
    expect(ENGINE_NAME).toBe("header-auditor-core");
  });

  it("keeps ENGINE_VERSION in sync with package.json", () => {
    expect(ENGINE_VERSION).toBe(pkg.version);
  });
});
