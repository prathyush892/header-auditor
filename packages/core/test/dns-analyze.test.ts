/** analyzeDns(): wiring, scoring and failure isolation. */
import { describe, expect, it } from "vitest";
import { analyzeDns, dnsUnavailable, Status } from "../src/index.js";
import { caa, fixtureResolver } from "./helpers/dns-fixture.js";

const D = "example.test";

const STRONG = {
  [D]: {
    txt: ["v=spf1 ip4:192.0.2.0/24 -all"],
    caa: [caa("issue", "ca.test"), caa("iodef", "mailto:s@example.test")],
  },
  [`_dmarc.${D}`]: { txt: ["v=DMARC1; p=reject; rua=mailto:d@example.test"] },
};

describe("analyzeDns", () => {
  it("grades a well-configured domain A", async () => {
    const report = await analyzeDns(D, { resolver: fixtureResolver(STRONG) });
    expect(report.findings.map((f) => f.status)).toEqual([Status.Pass, Status.Pass, Status.Pass]);
    expect(report).toMatchObject({ domain: D, earned: 45, maxScore: 45, score: 100, grade: "A" });
    expect(report.spf?.lookups).toBe(0);
    expect(Object.isFrozen(report)).toBe(true);
  });

  it("grades a domain with nothing configured F", async () => {
    const report = await analyzeDns(D, { resolver: fixtureResolver({}) });
    expect(report).toMatchObject({ earned: 0, maxScore: 45, grade: "F" });
  });

  it("normalises the domain before querying", async () => {
    const resolver = fixtureResolver(STRONG);
    const report = await analyzeDns(" Example.TEST. ", { resolver });
    expect(report.domain).toBe(D);
    expect(resolver.queries).toContain("TXT _dmarc.example.test");
  });

  it("isolates a failing lookup to its own check and drops it from the score", async () => {
    const report = await analyzeDns(D, {
      resolver: fixtureResolver({ ...STRONG, [`_dmarc.${D}`]: { fail: "SERVFAIL" } }),
    });
    const [caaF, spfF, dmarcF] = report.findings;
    expect(caaF?.status).toBe(Status.Pass);
    expect(spfF?.status).toBe(Status.Pass);
    expect(dmarcF).toMatchObject({ check: "DMARC", status: Status.Info, weight: 0 });
    expect(dmarcF?.detail).toMatch(/SERVFAIL/);
    expect(report).toMatchObject({ maxScore: 25, score: 100, dmarc: undefined });
  });

  it("passes the organizational domain through to DMARC discovery", async () => {
    const resolver = fixtureResolver({});
    await analyzeDns("shop.example.co.test", { resolver, organizationalDomain: "Example.co.test" });
    expect(resolver.queries).toContain("TXT _dmarc.example.co.test");
  });

  it("rejects an organizational domain that isn't a parent", async () => {
    await expect(
      analyzeDns(D, { resolver: fixtureResolver({}), organizationalDomain: "other.test" }),
    ).rejects.toThrow(/not a parent/);
  });

  it("rejects IPs and invalid names before any query", async () => {
    const resolver = fixtureResolver({});
    await expect(analyzeDns("127.0.0.1", { resolver })).rejects.toThrow(RangeError);
    await expect(analyzeDns("bad name", { resolver })).rejects.toThrow(RangeError);
    expect(resolver.queries).toEqual([]);
  });

  it("rethrows unexpected (non-DNS) errors", async () => {
    const resolver = {
      txt: () => Promise.reject(new TypeError("bug")),
      caa: () => Promise.resolve([]),
    };
    await expect(analyzeDns(D, { resolver })).rejects.toThrow("bug");
  });

  it("dnsUnavailable describes non-DNS errors generically", () => {
    expect(dnsUnavailable("SPF", new Error("x")).detail).toBe(
      "Could not be determined: lookup failed.",
    );
  });
});
