/** DMARC parsing, discovery and grading, using an in-memory resolver. */
import { describe, expect, it } from "vitest";
import {
  checkDmarc,
  DMARC_WEIGHT,
  isDmarcRecord,
  lookupDmarc,
  naiveOrganizationalDomain,
  parseDmarc,
  Status,
} from "../src/index.js";
import { fixtureResolver } from "./helpers/dns-fixture.js";

const D = "example.test";

describe("isDmarcRecord / parseDmarc", () => {
  it.each([
    ["v=DMARC1; p=none", true],
    ["v=dmarc1;p=reject", true],
    ["v = DMARC1 ; p=reject", true],
    ["v=DMARC1", true],
    ["p=reject; v=DMARC1", false],
    ["v=DMARC10; p=reject", false],
    ["v=spf1 -all", false],
  ])("isDmarcRecord(%j) = %s", (txt, expected) => {
    expect(isDmarcRecord(txt)).toBe(expected);
  });

  it("parses tags with defaults", () => {
    const r = parseDmarc("v=DMARC1; p=Reject; rua=mailto:a@x.test, mailto:b@y.test;");
    expect(r).toEqual({
      ok: true,
      record: {
        raw: "v=DMARC1; p=Reject; rua=mailto:a@x.test, mailto:b@y.test;",
        policy: "reject",
        subdomainPolicy: undefined,
        pct: 100,
        rua: ["mailto:a@x.test", "mailto:b@y.test"],
      },
    });
  });

  it("parses sp and pct", () => {
    const r = parseDmarc("v=DMARC1; p=quarantine; sp=none; pct=25");
    expect(r.ok && r.record).toMatchObject({ subdomainPolicy: "none", pct: 25 });
  });

  it.each([
    ["p=reject", /does not start/],
    ["v=DMARC1", /missing p/],
    ["v=DMARC1; p=block", /invalid p="block"/],
    ["v=DMARC1; p=reject; sp=maybe", /invalid sp/],
    ["v=DMARC1; p=reject; pct=101", /invalid pct/],
    ["v=DMARC1; p=reject; pct=-1", /invalid pct/],
    ["v=DMARC1; p=reject; pct=1000", /invalid pct/],
    ["v=DMARC1; p=reject; p=none", /duplicate tag "p"/],
    ["v=DMARC1; p=reject; junk", /malformed tag/],
  ])("rejects %j", (raw, message) => {
    const r = parseDmarc(raw);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(message);
  });
});

describe("lookupDmarc", () => {
  it("finds the record at _dmarc.<domain>", async () => {
    const obs = await lookupDmarc(
      D,
      fixtureResolver({ [`_dmarc.${D}`]: { txt: ["v=DMARC1; p=reject"] } }),
    );
    expect(obs).toMatchObject({ foundAt: "_dmarc.example.test", inherited: false });
    expect(obs.record?.policy).toBe("reject");
  });

  it("falls back to the organizational domain for subdomains", async () => {
    const resolver = fixtureResolver({
      [`_dmarc.${D}`]: { txt: ["v=DMARC1; p=reject; sp=quarantine"] },
    });
    const obs = await lookupDmarc(`mail.${D}`, resolver);
    expect(obs).toMatchObject({ foundAt: "_dmarc.example.test", inherited: true });
    expect(resolver.queries).toEqual(["TXT _dmarc.mail.example.test", "TXT _dmarc.example.test"]);
  });

  it("uses an explicit organizational domain", async () => {
    const resolver = fixtureResolver({});
    await lookupDmarc("shop.example.co.test", resolver, "example.co.test");
    expect(resolver.queries.at(-1)).toBe("TXT _dmarc.example.co.test");
  });

  it("doesn't query twice for an organizational domain", async () => {
    const resolver = fixtureResolver({});
    const obs = await lookupDmarc(D, resolver);
    expect(obs.foundAt).toBeUndefined();
    expect(resolver.queries).toEqual(["TXT _dmarc.example.test"]);
  });

  it("ignores non-DMARC TXT records and flags duplicates", async () => {
    const obs = await lookupDmarc(
      D,
      fixtureResolver({
        [`_dmarc.${D}`]: { txt: ["hello", "v=DMARC1; p=none", "v=DMARC1; p=reject"] },
      }),
    );
    expect(obs.error).toMatch(/2 DMARC records/);
    expect(obs.record).toBeUndefined();
  });

  it("reports parse errors", async () => {
    const obs = await lookupDmarc(
      D,
      fixtureResolver({ [`_dmarc.${D}`]: { txt: ["v=DMARC1; p=nah"] } }),
    );
    expect(obs.error).toMatch(/invalid p/);
  });

  it("naiveOrganizationalDomain keeps the last two labels", () => {
    expect(naiveOrganizationalDomain("a.b.example.test")).toBe("example.test");
    expect(naiveOrganizationalDomain("example.test")).toBe("example.test");
  });
});

describe("checkDmarc", () => {
  const grade = async (txt: string | undefined, domain = D) =>
    checkDmarc(
      await lookupDmarc(
        domain,
        fixtureResolver(txt === undefined ? {} : { [`_dmarc.${D}`]: { txt: [txt] } }),
      ),
    );

  it("fails when DMARC is missing", async () => {
    const f = await grade(undefined);
    expect(f).toMatchObject({ status: Status.Fail, score: 0, weight: DMARC_WEIGHT });
    expect(f.recommendation).toMatch(/p=none; rua=mailto:dmarc@example\.test/);
  });

  it("fails an invalid record", async () => {
    const f = await grade("v=DMARC1; pct=50");
    expect(f.status).toBe(Status.Fail);
    expect(f.detail).toMatch(/missing p tag/);
  });

  it.each([
    ["v=DMARC1; p=reject; rua=mailto:d@example.test", Status.Pass, 20],
    ["v=DMARC1; p=quarantine; rua=mailto:d@example.test", Status.Warn, 15],
    ["v=DMARC1; p=none; rua=mailto:d@example.test", Status.Warn, 5],
    ["v=DMARC1; p=reject; pct=50", Status.Warn, 10],
    ["v=DMARC1; p=quarantine; pct=10", Status.Warn, 10],
    ["v=DMARC1; p=none; pct=10", Status.Warn, 5],
    ["v=DMARC1; p=reject; sp=none", Status.Warn, 10],
    ["v=DMARC1; p=reject; sp=quarantine", Status.Pass, 20],
  ])("%j → %s (%i)", async (txt, status, score) => {
    expect(await grade(txt)).toMatchObject({ status, score });
  });

  it("applies sp to an inheriting subdomain", async () => {
    const f = await grade("v=DMARC1; p=reject; sp=none; rua=mailto:d@example.test", `www.${D}`);
    expect(f).toMatchObject({ status: Status.Warn, score: 5 });
    expect(f.detail).toMatch(/policy none \(inherited from _dmarc\.example\.test\)/);
  });

  it("falls back to p for an inheriting subdomain without sp", async () => {
    const f = await grade("v=DMARC1; p=reject; rua=mailto:d@example.test", `www.${D}`);
    expect(f).toMatchObject({ status: Status.Pass, score: 20 });
  });

  it("recommends reports and stronger policies", async () => {
    expect((await grade("v=DMARC1; p=none")).recommendation).toMatch(
      /^p=none only monitors.*Add rua=mailto/,
    );
    expect((await grade("v=DMARC1; p=quarantine; pct=50")).recommendation).toMatch(
      /Raise pct to 100.*p=reject/,
    );
    expect((await grade("v=DMARC1; p=reject; rua=mailto:d@example.test")).recommendation).toBe("");
  });
});
