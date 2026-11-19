/**
 * Unit tests for the Subresource Integrity check. Pure: HTML fixtures only,
 * no subresource is ever fetched.
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  buildContentReport,
  checkSubresourceIntegrity,
  findSriReferences,
  HeaderMap,
  isFirstPartyHost,
  parseIntegrity,
  SRI_CHECK,
  SRI_MAX_REFERENCES,
  SRI_WEIGHT,
  Status,
  type SriInput,
} from "../src/index.js";

const PAGE = "https://www.app.test/";
const digest = (alg: "sha256" | "sha384" | "sha512", data = "x"): string =>
  `${alg}-${createHash(alg).update(data).digest("base64")}`;
const SHA384 = digest("sha384");

function check(html: string, extra: Partial<SriInput> = {}) {
  return checkSubresourceIntegrity({ pageUrl: PAGE, html, ...extra });
}

describe("parseIntegrity", () => {
  it.each(["sha256", "sha384", "sha512"] as const)("accepts a well-formed %s digest", (alg) => {
    expect(parseIntegrity(digest(alg))).toEqual([alg]);
  });

  it("accepts base64url digests and missing padding", () => {
    const b64 = createHash("sha256").update("y").digest("base64");
    const url = b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(parseIntegrity(`sha256-${url}`)).toEqual(["sha256"]);
  });

  it("returns every recognised algorithm, weakest first, without duplicates", () => {
    const value = `  ${digest("sha512")}\n${digest("sha256")}\t${digest("sha256", "z")} `;
    expect(parseIntegrity(value)).toEqual(["sha256", "sha512"]);
  });

  it("ignores options after '?'", () => {
    expect(parseIntegrity(`${SHA384}?ct=application/javascript`)).toEqual(["sha384"]);
  });

  it.each([
    ["undefined", undefined],
    ["empty", ""],
    ["unknown algorithm", "md5-1B2M2Y8AsgTpgAmY7PhCfg=="],
    ["sha1", `sha1-${createHash("sha1").update("x").digest("base64")}`],
    ["upper-case algorithm", SHA384.replace("sha384", "SHA384")],
    ["no dash", "sha384"],
    ["empty digest", "sha384-"],
    ["leading dash", "-abc"],
    ["wrong digest length", `sha384-${createHash("sha256").update("x").digest("base64")}`],
    ["not base64", "sha256-not base64!!"],
    ["internal padding", "sha256-ab==cd"],
    ["a placeholder", "sha384-HASH_GOES_HERE"],
  ])("rejects %s", (_name, value) => {
    expect(parseIntegrity(value)).toEqual([]);
  });

  it("keeps the valid hash when another token is broken", () => {
    expect(parseIntegrity(`sha384-broken ${SHA384}`)).toEqual(["sha384"]);
  });
});

describe("isFirstPartyHost", () => {
  it.each([
    ["www.app.test", "www.app.test"],
    ["app.test", "www.app.test"],
    ["static.app.test", "www.app.test"],
    ["a.b.app.test", "app.test"],
    ["APP.TEST.", "app.test"],
  ])("%s is first-party for %s", (host, page) => {
    expect(isFirstPartyHost(host, page)).toBe(true);
  });

  it.each([
    ["cdn.test", "www.app.test"],
    ["evilapp.test", "app.test"],
    ["app.test.evil.test", "app.test"],
    ["www.app.test", "shop.app.test"],
    ["127.0.0.2", "127.0.0.1"],
  ])("%s is third-party for %s", (host, page) => {
    expect(isFirstPartyHost(host, page)).toBe(false);
  });

  it("honours extra first-party hosts, exactly", () => {
    expect(
      isFirstPartyHost("assets.example-cdn.test", "app.test", ["Assets.Example-CDN.test"]),
    ).toBe(true);
    expect(
      isFirstPartyHost("x.assets.example-cdn.test", "app.test", ["assets.example-cdn.test"]),
    ).toBe(false);
  });
});

describe("findSriReferences", () => {
  it("collects third-party scripts and stylesheets with their status", () => {
    const refs = findSriReferences(
      `<script src="https://cdn.test/a.js"></script>
       <script src="https://cdn.test/b.js" integrity="${SHA384}" crossorigin="anonymous"></script>
       <link rel="stylesheet" href="https://fonts.test/c.css" integrity="${SHA384}">
       <link rel=stylesheet href="//cdn.test/d.css#frag" integrity="sha384-nope" crossorigin>`,
      PAGE,
    );
    expect(refs.map((r) => [r.type, r.url, r.status])).toEqual([
      ["script", "https://cdn.test/a.js", "missing"],
      ["script", "https://cdn.test/b.js", "protected"],
      ["stylesheet", "https://fonts.test/c.css", "no-cors"],
      ["stylesheet", "https://cdn.test/d.css", "invalid"],
    ]);
    expect(refs[1]?.algorithms).toEqual(["sha384"]);
    expect(refs[3]?.crossorigin).toBe("");
  });

  it("skips same-origin, first-party subdomain and non-network references", () => {
    const refs = findSriReferences(
      `<script src="/app.js"></script>
       <script src="https://static.app.test/vendor.js"></script>
       <script src="data:text/javascript,1"></script>
       <script src="blob:https://www.app.test/x"></script>
       <script src="javascript:alert(1)"></script>
       <script src="http://[::1"></script>
       <link rel="stylesheet" href="  ">`,
      PAGE,
    );
    expect(refs).toEqual([]);
  });

  it("ignores inline scripts, data blocks and non-script links", () => {
    const refs = findSriReferences(
      `<script>var x = 1</script>
       <script type="application/ld+json" src="https://cdn.test/data.json"></script>
       <script type="text/template" src="https://cdn.test/t.html"></script>
       <script type="importmap" src="https://cdn.test/map.json"></script>
       <link rel="icon" href="https://cdn.test/favicon.ico">
       <link rel="preconnect" href="https://cdn.test">
       <link rel="preload" as="image" href="https://cdn.test/hero.png">
       <link rel="preload" as="font" href="https://cdn.test/f.woff2">`,
      PAGE,
    );
    expect(refs).toEqual([]);
  });

  it("recognises preload, modulepreload and alternate stylesheets", () => {
    const refs = findSriReferences(
      `<link rel="preload" as="script" href="https://cdn.test/p.js">
       <link rel="preload" as="style" href="https://cdn.test/p.css">
       <link rel="alternate stylesheet" href="https://cdn.test/alt.css">
       <link rel="modulepreload" href="https://cdn.test/m.js">
       <script type="text/javascript" src="https://cdn.test/classic.js"></script>`,
      PAGE,
    );
    expect(refs.map((r) => [r.tag, r.type])).toEqual([
      ["link", "script"],
      ["link", "stylesheet"],
      ["link", "stylesheet"],
      ["link", "script"],
      ["script", "script"],
    ]);
  });

  it("treats module scripts and modulepreload as CORS fetches without crossorigin", () => {
    const refs = findSriReferences(
      `<script type="module" src="https://cdn.test/m.js" integrity="${SHA384}"></script>
       <link rel="modulepreload" href="https://cdn.test/n.js" integrity="${SHA384}">
       <script src="https://cdn.test/c.js" integrity="${SHA384}"></script>`,
      PAGE,
    );
    expect(refs.map((r) => r.status)).toEqual(["protected", "protected", "no-cors"]);
  });

  it("resolves relative URLs against <base href>", () => {
    const refs = findSriReferences(
      `<base href="https://cdn.test/v1/"><script src="lib.js"></script>`,
      PAGE,
    );
    expect(refs.map((r) => r.url)).toEqual(["https://cdn.test/v1/lib.js"]);
  });

  it("decodes entities and is case-insensitive on tags and attributes", () => {
    const refs = findSriReferences(
      `<SCRIPT SRC="https://cdn.test/a.js?x=1&amp;y=2" INTEGRITY="${SHA384}" CrossOrigin="anonymous"></SCRIPT>`,
      PAGE,
    );
    expect(refs).toHaveLength(1);
    expect(refs[0]?.url).toBe("https://cdn.test/a.js?x=1&y=2");
    expect(refs[0]?.status).toBe("protected");
  });

  it("does not trip over prototype-named attributes", () => {
    const refs = findSriReferences(
      '<script constructor="x" __proto__="y" src="https://cdn.test/a.js"></script>',
      PAGE,
    );
    expect(refs.map((r) => r.status)).toEqual(["missing"]);
  });

  it("ignores markup inside comments", () => {
    expect(
      findSriReferences('<!-- <script src="https://cdn.test/a.js"></script> -->', PAGE),
    ).toEqual([]);
  });

  it(`stops collecting after ${String(SRI_MAX_REFERENCES)} references`, () => {
    const html = '<script src="https://cdn.test/a.js"></script>'.repeat(SRI_MAX_REFERENCES + 50);
    expect(findSriReferences(html, PAGE)).toHaveLength(SRI_MAX_REFERENCES);
  });

  it("uses extra first-party hosts", () => {
    const html = '<script src="https://assets.cdn.test/a.js"></script>';
    expect(findSriReferences(html, PAGE, ["assets.cdn.test"])).toEqual([]);
  });
});

describe("checkSubresourceIntegrity", () => {
  it("is informational for non-HTML responses", () => {
    const { finding, references } = checkSubresourceIntegrity({ pageUrl: PAGE, html: undefined });
    expect(finding.status).toBe(Status.Info);
    expect(finding.weight).toBe(0);
    expect(references).toEqual([]);
  });

  it("passes a page with no third-party scripts or stylesheets", () => {
    const { finding } = check('<script src="/app.js"></script><img src="https://cdn.test/a.png">');
    expect(finding).toMatchObject({
      check: SRI_CHECK,
      status: Status.Pass,
      score: SRI_WEIGHT,
      weight: SRI_WEIGHT,
    });
    expect(finding.detail).toMatch(/No third-party/);
  });

  it("passes when every third-party resource is pinned and CORS-fetched", () => {
    const { finding, references } = check(
      `<script src="https://cdn.test/a.js" integrity="${SHA384}" crossorigin="anonymous"></script>
       <link rel="stylesheet" href="https://cdn.test/a.css" integrity="${digest("sha512")}" crossorigin>`,
    );
    expect(finding.status).toBe(Status.Pass);
    expect(finding.score).toBe(SRI_WEIGHT);
    expect(finding.detail).toMatch(/All 2 third-party/);
    expect(references).toHaveLength(2);
  });

  it("fails an unpinned third-party script", () => {
    const { finding } = check(
      `<script src="https://cdn.test/a.js"></script>
       <link rel="stylesheet" href="https://cdn.test/a.css" integrity="${SHA384}" crossorigin>`,
    );
    expect(finding.status).toBe(Status.Fail);
    expect(finding.score).toBe(0);
    expect(finding.detail).toMatch(/1 of 2 third-party/);
    expect(finding.detail).toContain("https://cdn.test/a.js");
    expect(finding.recommendation).toMatch(/sha384/);
  });

  it("fails a script whose integrity value is unusable, and says why", () => {
    const { finding } = check(
      '<script src="https://cdn.test/a.js" integrity="md5-abc" crossorigin></script>',
    );
    expect(finding.status).toBe(Status.Fail);
    expect(finding.detail).toMatch(/unusable integrity value/);
  });

  it("warns (5) when only stylesheets are unpinned", () => {
    const { finding } = check('<link rel="stylesheet" href="https://fonts.test/css">');
    expect(finding.status).toBe(Status.Warn);
    expect(finding.score).toBe(5);
    expect(finding.detail).toMatch(/stylesheets/);
  });

  it("warns (8) when hashes are valid but crossorigin is missing", () => {
    const { finding } = check(
      `<script src="https://cdn.test/a.js" integrity="${SHA384}"></script>`,
    );
    expect(finding.status).toBe(Status.Warn);
    expect(finding.score).toBe(8);
    expect(finding.recommendation).toMatch(/crossorigin="anonymous"/);
  });

  it("summarises long lists", () => {
    const html = Array.from(
      { length: 8 },
      (_, i) => `<script src="https://cdn.test/${String(i)}.js"></script>`,
    ).join("");
    const { finding } = check(html);
    expect(finding.detail).toMatch(/and 3 more$/);
  });

  it("notes a truncated body", () => {
    expect(check("<p>hi</p>", { truncated: true }).finding.detail).toMatch(/only the first part/);
  });

  it("applies to http pages too (a compromised CDN is a CDN compromise either way)", () => {
    const { finding } = checkSubresourceIntegrity({
      pageUrl: "http://app.test/",
      html: '<script src="https://cdn.test/a.js"></script>',
    });
    expect(finding.status).toBe(Status.Fail);
  });
});

describe("buildContentReport with SRI", () => {
  const base = {
    pageUrl: PAGE,
    headers: new HeaderMap({}),
    redirects: [],
    bodyBytes: 100,
    bodyTruncated: false,
  };

  it("adds the SRI finding as the third content finding and lists references", () => {
    const report = buildContentReport({
      ...base,
      html: '<script src="https://cdn.test/a.js"></script>',
    });
    expect(report.findings.map((f) => f.check)).toEqual([
      "Redirect chain",
      "Mixed content",
      SRI_CHECK,
    ]);
    expect(report.subresourceIntegrity.map((r) => r.status)).toEqual(["missing"]);
    // Mixed content passes (15/15), SRI fails (0/10): 60%.
    expect(report.score).toBe(60);
  });

  it("passes firstPartyHosts through", () => {
    const report = buildContentReport({
      ...base,
      html: '<script src="https://cdn.test/a.js"></script>',
      firstPartyHosts: ["cdn.test"],
    });
    expect(report.subresourceIntegrity).toEqual([]);
    expect(report.findings[2]?.status).toBe(Status.Pass);
  });
});
