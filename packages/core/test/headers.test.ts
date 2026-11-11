import { describe, expect, it } from "vitest";
import { HeaderMap } from "../src/index.js";

describe("HeaderMap", () => {
  it("is case-insensitive and keeps every value of repeated headers", () => {
    const h = new HeaderMap([
      ["Set-Cookie", "a=1"],
      ["set-cookie", "b=2"],
      ["X-TEST", "x"],
    ]);
    expect(h.get("x-test")).toBe("x");
    expect(h.getAll("SET-COOKIE")).toEqual(["a=1", "b=2"]);
    expect(h.has("X-Test")).toBe(true);
  });

  it("returns the first value from get() and undefined / [] when absent", () => {
    const h = new HeaderMap([
      ["A", "1"],
      ["a", "2"],
    ]);
    expect(h.get("a")).toBe("1");
    expect(h.get("missing")).toBeUndefined();
    expect(h.getAll("missing")).toEqual([]);
    expect(h.has("missing")).toBe(false);
  });

  it("trims surrounding whitespace from values", () => {
    expect(new HeaderMap([["X", "  v \t"]]).get("x")).toBe("v");
  });

  it("builds from a plain record, including array values, skipping undefined", () => {
    const h = new HeaderMap({ "Set-Cookie": ["a=1", "b=2"], Server: "nginx", Skip: undefined });
    expect(h.getAll("set-cookie")).toEqual(["a=1", "b=2"]);
    expect(h.get("server")).toBe("nginx");
    expect(h.has("skip")).toBe(false);
  });

  it("builds from WHATWG Headers without merging Set-Cookie lines", () => {
    const web = new Headers();
    web.append("Set-Cookie", "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT");
    web.append("Set-Cookie", "b=2");
    web.append("Referrer-Policy", "no-referrer");
    const h = new HeaderMap(web);
    expect(h.getAll("set-cookie")).toEqual(["a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT", "b=2"]);
    expect(h.get("referrer-policy")).toBe("no-referrer");
  });

  it("does not let callers mutate internal state through getAll()", () => {
    const h = new HeaderMap([["A", "1"]]);
    h.getAll("a").push("evil");
    expect(h.getAll("a")).toEqual(["1"]);
  });

  it.each(["", "Bad Name", "x:y", "naïve", "a\nb"])("rejects invalid header name %j", (name) => {
    expect(() => new HeaderMap([[name, "v"]])).toThrow(TypeError);
  });

  it.each(["a\r\nInjected: 1", "a\nb", "a\0b"])("rejects CR/LF/NUL in value %j", (value) => {
    expect(() => new HeaderMap([["X", value]])).toThrow(TypeError);
  });

  it("defaults to an empty map", () => {
    expect(new HeaderMap().get("anything")).toBeUndefined();
  });
});
