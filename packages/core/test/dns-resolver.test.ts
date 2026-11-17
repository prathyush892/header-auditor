/** Domain validation and the real node:dns resolver against a local DNS server. */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  analyzeDns,
  caaFromNode,
  createDnsResolver,
  DnsLookupError,
  dnsTargetFromUrl,
  normalizeDomain,
  parentDomains,
  Status,
} from "../src/index.js";
import { startDnsServer, type DnsTestServer } from "./helpers/dns-server.js";

describe("normalizeDomain", () => {
  it.each([
    ["Example.TEST", "example.test"],
    ["  app.example.test. ", "app.example.test"],
    ["bücher.example", "xn--bcher-kva.example"],
    ["_dmarc.example.test", "_dmarc.example.test"],
  ])("normalises %j", (input, expected) => {
    expect(normalizeDomain(input)).toBe(expected);
  });

  it.each([
    ["", /empty/],
    ["localhost", /fully qualified/],
    ["192.0.2.1", /IP address/],
    ["[::1]", /IP address/],
    ["1.2.3.4.5", /Invalid|IP address/],
    ["-bad.example.test", /Invalid/],
    ["a..b.test", /Invalid/],
    ["exa mple.test", /Invalid/],
    [`${"a".repeat(64)}.test`, /Invalid/],
    [`${"a.".repeat(127)}test`, /Invalid/],
  ])("rejects %j", (input, message) => {
    expect(() => normalizeDomain(input)).toThrow(message);
  });

  it("rejects non-strings", () => {
    expect(() => normalizeDomain(42 as unknown as string)).toThrow(TypeError);
  });

  it("extracts the host from a URL", () => {
    expect(dnsTargetFromUrl("https://WWW.Example.test:8443/path?q")).toBe("www.example.test");
    expect(() => dnsTargetFromUrl("https://127.0.0.1/")).toThrow(/IP address/);
  });

  it("lists parents nearest first, excluding the TLD", () => {
    expect(parentDomains("a.b.example.test")).toEqual(["b.example.test", "example.test"]);
    expect(parentDomains("example.test")).toEqual([]);
  });
});

describe("caaFromNode", () => {
  it("maps node's one-key-per-tag shape and the critical bit", () => {
    expect(caaFromNode({ critical: 0, issue: "ca.test" })).toEqual({
      critical: false,
      tag: "issue",
      value: "ca.test",
    });
    expect(caaFromNode({ critical: 128, Iodef: "mailto:x@y.test" })).toMatchObject({
      critical: true,
      tag: "iodef",
    });
    expect(caaFromNode({ critical: 0 })).toBeUndefined();
  });
});

describe("createDnsResolver options", () => {
  it.each([
    [{ timeoutMs: 0 }, /timeoutMs/],
    [{ timeoutMs: 30_001 }, /timeoutMs/],
    [{ timeoutMs: 1.5 }, /timeoutMs/],
    [{ tries: 0 }, /tries/],
    [{ tries: 6 }, /tries/],
    [{ servers: [] }, /servers/],
  ])("rejects %j", (options, message) => {
    expect(() => createDnsResolver(options)).toThrow(message);
  });
});

describe("createDnsResolver against a local DNS server", () => {
  let server: DnsTestServer;

  beforeAll(async () => {
    server = await startDnsServer({
      "example.test": {
        txt: [["v=spf1 ip4:192.0.2.0/24 ", "-all"], ["google-site-verification=abc"]],
        caa: [
          { flags: 0, tag: "issue", value: "ca.test" },
          { flags: 128, tag: "iodef", value: "mailto:security@example.test" },
        ],
      },
      "_dmarc.example.test": { txt: [["v=DMARC1; p=reject; rua=mailto:d@example.test"]] },
      "empty.example.test": {},
      "broken.example.test": { rcode: "SERVFAIL" },
      "refused.example.test": { rcode: "REFUSED" },
      "slow.example.test": { drop: true },
    });
  });

  afterAll(async () => {
    await server.close();
  });

  const resolver = () => createDnsResolver({ servers: [server.address], timeoutMs: 150, tries: 1 });

  it("joins TXT character-strings into one record", async () => {
    expect(await resolver().txt("example.test")).toEqual([
      "v=spf1 ip4:192.0.2.0/24 -all",
      "google-site-verification=abc",
    ]);
  });

  it("parses CAA records", async () => {
    expect(await resolver().caa("example.test")).toEqual([
      { critical: false, tag: "issue", value: "ca.test" },
      { critical: true, tag: "iodef", value: "mailto:security@example.test" },
    ]);
  });

  it("returns [] for NODATA and NXDOMAIN", async () => {
    const r = resolver();
    expect(await r.txt("empty.example.test")).toEqual([]);
    expect(await r.caa("empty.example.test")).toEqual([]);
    expect(await r.txt("missing.example.test")).toEqual([]);
  });

  it.each([
    ["broken.example.test", "SERVFAIL"],
    ["refused.example.test", "REFUSED"],
    ["slow.example.test", "TIMEOUT"],
  ])("maps %s to %s", async (name, code) => {
    const err: unknown = await resolver()
      .txt(name)
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DnsLookupError);
    expect(err).toMatchObject({ code, qname: name, rrtype: "TXT" });
  });

  it("runs the full analysis end to end", async () => {
    const report = await analyzeDns("example.test", { resolver: resolver() });
    expect(report.findings.map((f) => [f.check, f.status])).toEqual([
      ["CAA", Status.Pass],
      ["SPF", Status.Pass],
      ["DMARC", Status.Pass],
    ]);
    expect(report).toMatchObject({ score: 100, grade: "A", domain: "example.test" });
  });

  it("turns a failing lookup into an unscored info finding", async () => {
    const report = await analyzeDns("slow.example.test", { resolver: resolver() });
    const spf = report.findings.find((f) => f.check === "SPF");
    expect(spf).toMatchObject({ status: Status.Info, weight: 0 });
    expect(spf?.detail).toMatch(/TIMEOUT/);
    expect(report.spf).toBeUndefined();
  });
});
