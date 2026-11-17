/** CAA tree climbing and grading, using an in-memory resolver. */
import { describe, expect, it } from "vitest";
import { CAA_WEIGHT, caaIssuer, checkCaa, lookupCaa, Status } from "../src/index.js";
import { caa, fixtureResolver } from "./helpers/dns-fixture.js";

const D = "example.test";

describe("caaIssuer", () => {
  it.each([
    ["letsencrypt.org", "letsencrypt.org"],
    ["  Pki.Goog ; accounturi=https://x", "pki.goog"],
    [";", ""],
    ["", ""],
    ["not a domain", undefined],
    ["nodot", undefined],
    ["under_score.test", undefined],
  ])("%j → %j", (value, expected) => {
    expect(caaIssuer(value)).toBe(expected);
  });
});

describe("lookupCaa", () => {
  it("uses the domain's own records first", async () => {
    const resolver = fixtureResolver({ [`www.${D}`]: { caa: [caa("issue", "ca.test")] } });
    const obs = await lookupCaa(`www.${D}`, resolver);
    expect(obs.foundAt).toBe("www.example.test");
    expect(resolver.queries).toEqual(["CAA www.example.test"]);
  });

  it("climbs to the closest parent with CAA (RFC 8659 §3)", async () => {
    const resolver = fixtureResolver({ [D]: { caa: [caa("issue", "ca.test")] } });
    const obs = await lookupCaa(`a.b.${D}`, resolver);
    expect(obs.foundAt).toBe("example.test");
    expect(resolver.queries).toEqual([
      "CAA a.b.example.test",
      "CAA b.example.test",
      "CAA example.test",
    ]);
  });

  it("stops before the TLD when nothing is found", async () => {
    const resolver = fixtureResolver({});
    const obs = await lookupCaa(`www.${D}`, resolver);
    expect(obs).toMatchObject({ foundAt: undefined, records: [] });
    expect(resolver.queries).not.toContain("CAA test");
  });
});

describe("checkCaa", () => {
  const grade = async (records: ReturnType<typeof caa>[], domain = D) =>
    checkCaa(
      await lookupCaa(domain, fixtureResolver(records.length ? { [D]: { caa: records } } : {})),
    );

  it("warns without CAA", async () => {
    const f = await grade([]);
    expect(f).toMatchObject({ status: Status.Warn, score: 0, weight: CAA_WEIGHT });
    expect(f.recommendation).toMatch(/0 issue "letsencrypt\.org"/);
  });

  it("passes when issuance is restricted and reporting is set up", async () => {
    const f = await grade([caa("issue", "ca.test"), caa("iodef", "mailto:s@example.test")]);
    expect(f).toMatchObject({ status: Status.Pass, score: CAA_WEIGHT, recommendation: "" });
    expect(f.detail).toBe("CAA restricts issuance (issue: ca.test).");
  });

  it("suggests iodef when missing", async () => {
    const f = await grade([caa("issue", "ca.test"), caa("issuewild", ";")]);
    expect(f.status).toBe(Status.Pass);
    expect(f.detail).toMatch(/issue: ca\.test; issuewild: \(none\)/);
    expect(f.recommendation).toMatch(/iodef/);
  });

  it("notes inheritance", async () => {
    const f = await grade([caa("issue", "ca.test")], `api.${D}`);
    expect(f.detail).toMatch(/inherited from example\.test/);
  });

  it('treats issue ";" (no CA may issue) as restrictive', async () => {
    expect((await grade([caa("issue", ";")])).status).toBe(Status.Pass);
  });

  it.each([
    [[caa("iodef", "mailto:s@example.test")], /doesn't restrict/],
    [[caa("issuewild", "ca.test")], /only restricts wildcard/],
  ])("warns when no issue property is present", async (records, detail) => {
    const f = await grade(records);
    expect(f).toMatchObject({ status: Status.Warn, score: 5 });
    expect(f.detail).toMatch(detail);
  });

  it("warns on unknown critical tags", async () => {
    const f = await grade([caa("issue", "ca.test"), caa("futuretag", "x", true)]);
    expect(f).toMatchObject({ status: Status.Warn, score: 5 });
    expect(f.detail).toMatch(/unknown critical tag\(s\) futuretag/);
  });

  it("ignores unknown non-critical tags and known critical ones", async () => {
    const f = await grade([caa("issue", "ca.test", true), caa("futuretag", "x")]);
    expect(f.status).toBe(Status.Pass);
  });

  it("warns on malformed issue values", async () => {
    const f = await grade([caa("issue", "not a ca")]);
    expect(f).toMatchObject({ status: Status.Warn, score: 5 });
    expect(f.detail).toMatch(/invalid "not a ca"/);
  });
});
