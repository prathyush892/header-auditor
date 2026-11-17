/** SPF parsing, include/redirect walking and grading, using an in-memory resolver. */
import { describe, expect, it } from "vitest";
import {
  checkSpf,
  DnsLookupError,
  isSpfRecord,
  lookupSpf,
  parseSpf,
  SPF_LOOKUP_LIMIT,
  SPF_WEIGHT,
  Status,
} from "../src/index.js";
import { fixtureResolver } from "./helpers/dns-fixture.js";

const D = "example.test";

describe("isSpfRecord", () => {
  it.each([
    ["v=spf1 -all", true],
    ["V=SPF1", true],
    ["v=spf10 -all", false],
    ["v=spf1-all", false],
    ["google-site-verification=x", false],
  ])("%j → %s", (txt, expected) => {
    expect(isSpfRecord(txt)).toBe(expected);
  });
});

describe("parseSpf", () => {
  it("parses qualifiers, targets, prefixes and redirect", () => {
    const r = parseSpf(
      "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:mail.example.test/24//64 ~include:_spf.mail.test exists:%{i}.x.test ?ptr redirect=other.test exp=explain.test unknown=ok -all",
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.record.redirect).toBe("other.test");
    expect(r.record.mechanisms.map((m) => `${m.qualifier}${m.name}:${m.target}`)).toEqual([
      "+ip4:192.0.2.0",
      "+ip6:2001:db8::",
      "+a:",
      "+mx:mail.example.test",
      "~include:_spf.mail.test",
      "+exists:%{i}.x.test",
      "?ptr:",
      "-all:",
    ]);
  });

  it("tolerates repeated spaces and mixed case", () => {
    const r = parseSpf("v=spf1   IP4:192.0.2.1   -ALL");
    expect(r.ok && r.record.mechanisms.map((m) => m.name)).toEqual(["ip4", "all"]);
  });

  it.each([
    ["v=spf2 -all", /v=spf1/],
    ["v=spf1 include", /needs a value/],
    ["v=spf1 ip4:999.0.0.1", /invalid ip4/],
    ["v=spf1 ip4:192.0.2.0/33", /invalid ip4/],
    ["v=spf1 ip6:192.0.2.1", /invalid ip6/],
    ["v=spf1 ip6:2001:db8::/129", /invalid ip6/],
    ["v=spf1 ip4:192.0.2.0//64", /prefix length/],
    ["v=spf1 a/40", /prefix length/],
    ["v=spf1 mx//200", /prefix length/],
    ["v=spf1 a/", /unknown term/],
    ["v=spf1 a/x", /unknown term/],
    ["v=spf1 include:x.test/24", /takes no prefix/],
    ["v=spf1 all:x", /takes no value/],
    ["v=spf1 -all/24", /takes no value/],
    ["v=spf1 redirect=a.test redirect=b.test", /more than once/],
    ["v=spf1 redirect=", /needs a domain/],
    ["v=spf1 +foo -all", /unknown term "\+foo"/],
  ])("rejects %j", (raw, message) => {
    const r = parseSpf(raw);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(message);
  });
});

describe("lookupSpf", () => {
  it("returns no record when the domain has none", async () => {
    const obs = await lookupSpf(D, fixtureResolver({ [D]: { txt: ["something else"] } }));
    expect(obs).toMatchObject({ records: [], record: undefined, permerror: undefined });
  });

  it("flags multiple SPF records as permerror", async () => {
    const obs = await lookupSpf(
      D,
      fixtureResolver({ [D]: { txt: ["v=spf1 -all", "v=spf1 a -all"] } }),
    );
    expect(obs.permerror).toMatch(/2 SPF records/);
  });

  it("counts lookups across nested includes", async () => {
    const resolver = fixtureResolver({
      [D]: { txt: ["v=spf1 a mx include:one.test ip4:192.0.2.1 -all"] },
      "one.test": { txt: ["v=spf1 include:two.test exists:x.test ~all"] },
      "two.test": { txt: ["v=spf1 ip4:198.51.100.0/24 ?all"] },
    });
    const obs = await lookupSpf(D, resolver);
    // a, mx, include:one, include:two, exists = 5
    expect(obs).toMatchObject({ lookups: 5, all: "-", complete: true, permerror: undefined });
    expect(resolver.queries).toEqual(["TXT example.test", "TXT one.test", "TXT two.test"]);
  });

  it("reports permerror past the 10-lookup limit and stops querying", async () => {
    const includes = Array.from({ length: 12 }, (_, i) => `include:i${String(i)}.test`);
    const zone = Object.fromEntries(
      Array.from({ length: 12 }, (_, i) => [
        `i${String(i)}.test`,
        { txt: ["v=spf1 ip4:192.0.2.1 -all"] },
      ]),
    );
    const resolver = fixtureResolver({
      ...zone,
      [D]: { txt: [`v=spf1 ${includes.join(" ")} -all`] },
    });
    const obs = await lookupSpf(D, resolver);
    expect(obs.lookups).toBe(SPF_LOOKUP_LIMIT + 1);
    expect(obs.permerror).toMatch(/more than 10 DNS lookups/);
    expect(resolver.queries.length).toBeLessThanOrEqual(SPF_LOOKUP_LIMIT + 1);
  });

  it("follows redirect when there is no all", async () => {
    const obs = await lookupSpf(
      D,
      fixtureResolver({
        [D]: { txt: ["v=spf1 redirect=_spf.example.test"] },
        "_spf.example.test": { txt: ["v=spf1 ip4:192.0.2.1 -all"] },
      }),
    );
    expect(obs).toMatchObject({ all: "-", lookups: 1, permerror: undefined });
  });

  it("ignores redirect when all is present", async () => {
    const resolver = fixtureResolver({ [D]: { txt: ["v=spf1 ~all redirect=elsewhere.test"] } });
    const obs = await lookupSpf(D, resolver);
    expect(obs).toMatchObject({ all: "~", lookups: 0 });
    expect(resolver.queries).toEqual(["TXT example.test"]);
  });

  it("treats an include without SPF as permerror", async () => {
    const obs = await lookupSpf(
      D,
      fixtureResolver({ [D]: { txt: ["v=spf1 include:gone.test -all"] } }),
    );
    expect(obs.permerror).toBe("gone.test has no SPF record");
  });

  it("reports invalid nested records", async () => {
    const obs = await lookupSpf(
      D,
      fixtureResolver({
        [D]: { txt: ["v=spf1 include:bad.test -all"] },
        "bad.test": { txt: ["v=spf1 ip4:nope -all"] },
      }),
    );
    expect(obs.permerror).toMatch(/^bad\.test: invalid ip4/);
  });

  it("detects include loops", async () => {
    const obs = await lookupSpf(
      D,
      fixtureResolver({
        [D]: { txt: ["v=spf1 include:a.test -all"] },
        "a.test": { txt: ["v=spf1 include:example.test -all"] },
      }),
    );
    expect(obs.permerror).toMatch(/loop through example\.test/);
  });

  it("marks the walk incomplete for macros and failed nested lookups", async () => {
    const obs = await lookupSpf(
      D,
      fixtureResolver({
        [D]: { txt: ["v=spf1 include:%{d}.x.test include:flaky.test -all"] },
        "flaky.test": { fail: "TIMEOUT" },
      }),
    );
    expect(obs).toMatchObject({ complete: false, permerror: undefined, lookups: 2 });
  });

  it("records ptr usage", async () => {
    const obs = await lookupSpf(D, fixtureResolver({ [D]: { txt: ["v=spf1 ptr -all"] } }));
    expect(obs).toMatchObject({ usesPtr: true, lookups: 1 });
  });

  it("throws when the top-level lookup fails", async () => {
    await expect(
      lookupSpf(D, fixtureResolver({ [D]: { fail: "SERVFAIL" } })),
    ).rejects.toBeInstanceOf(DnsLookupError);
  });
});

describe("checkSpf", () => {
  const grade = async (txt: string[], extra = {}) =>
    checkSpf(await lookupSpf(D, fixtureResolver({ [D]: { txt }, ...extra })));

  it("fails when SPF is missing", async () => {
    const f = await grade([]);
    expect(f).toMatchObject({ status: Status.Fail, score: 0, weight: SPF_WEIGHT });
    expect(f.recommendation).toMatch(/v=spf1 -all/);
  });

  it.each([
    ["v=spf1 ip4:192.0.2.1 -all", Status.Pass, 15],
    ["v=spf1 -all", Status.Pass, 15],
    ["v=spf1 ip4:192.0.2.1 ~all", Status.Warn, 10],
    ["v=spf1 ip4:192.0.2.1 ?all", Status.Warn, 5],
    ["v=spf1 ip4:192.0.2.1", Status.Warn, 5],
    ["v=spf1 ip4:192.0.2.1 +all", Status.Fail, 0],
    ["v=spf1 all", Status.Fail, 0],
    ["v=spf1 ptr -all", Status.Warn, 10],
    ["v=spf1 ip4:bad -all", Status.Fail, 0],
  ])("%j → %s (%i)", async (txt, status, score) => {
    expect(await grade([txt])).toMatchObject({ status, score });
  });

  it("explains a permerror", async () => {
    const f = await grade(["v=spf1 -all", "v=spf1 ~all"]);
    expect(f.status).toBe(Status.Fail);
    expect(f.detail).toMatch(/permerror/);
  });

  it("includes the lookup count and incomplete note in the detail", async () => {
    const f = await grade(["v=spf1 include:flaky.test -all"], {
      "flaky.test": { fail: "TIMEOUT" },
    });
    expect(f.detail).toMatch(/1\/10 DNS lookups; some includes could not be followed/);
  });

  it("recommends removing ptr", async () => {
    expect((await grade(["v=spf1 ptr -all"])).recommendation).toMatch(/Remove "ptr"/);
  });
});
