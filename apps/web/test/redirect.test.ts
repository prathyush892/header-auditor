import { describe, expect, it } from "vitest";

import { DEFAULT_AFTER_LOGIN, loginUrlFor, safeNextPath } from "@/lib/redirect";

describe("safeNextPath", () => {
  it.each([
    ["/dashboard", "/dashboard"],
    ["/sites/abc?tab=history#latest", "/sites/abc?tab=history#latest"],
    ["/sites/../dashboard", "/dashboard"],
    ["/search?q=%2F%2Fevil", "/search?q=%2F%2Fevil"],
  ])("keeps same-origin path %s", (input, expected) => {
    expect(safeNextPath(input)).toBe(expected);
  });

  it.each([
    ["absolute URL", "https://evil.example/phish"],
    ["protocol-relative", "//evil.example"],
    ["backslash protocol-relative", "/\\evil.example"],
    ["backslash later in path", "/foo\\..\\\\evil.example"],
    ["javascript: URL", "javascript:alert(1)"],
    ["data: URL", "data:text/html,hi"],
    ["relative path", "dashboard"],
    ["tab smuggling", "/\t/evil.example"],
    ["newline smuggling", "/\n/evil.example"],
    ["empty", ""],
    ["login page (loop)", "/login"],
    ["register page (loop)", "/register?next=/x"],
    ["login subpath", "/login/extra"],
    ["very long", `/${"a".repeat(3_000)}`],
  ])("falls back for %s", (_label, input) => {
    expect(safeNextPath(input)).toBe(DEFAULT_AFTER_LOGIN);
  });

  it("falls back for null and undefined, with a custom fallback", () => {
    expect(safeNextPath(null)).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath(undefined, "/home")).toBe("/home");
  });

  it("does not treat /loginx as the login page", () => {
    expect(safeNextPath("/loginx")).toBe("/loginx");
  });
});

describe("loginUrlFor", () => {
  it("omits next for the default destination", () => {
    expect(loginUrlFor("/dashboard")).toBe("/login");
  });

  it("encodes the current path", () => {
    expect(loginUrlFor("/dashboard/sites?x=1&y=2")).toBe(
      "/login?next=%2Fdashboard%2Fsites%3Fx%3D1%26y%3D2",
    );
  });

  it("drops an unsafe current path", () => {
    expect(loginUrlFor("//evil.example")).toBe("/login");
  });
});
