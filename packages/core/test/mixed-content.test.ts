/**
 * Pure tests for HTML resource extraction and the mixed-content check. The
 * URLs below are strings in fixtures; nothing is ever fetched.
 */
import { describe, expect, it } from "vitest";
import {
  checkMixedContent,
  cssUrls,
  extractResources,
  findMixedContent,
  hasUpgradeInsecureRequests,
  HeaderMap,
  isPotentiallyTrustworthyHost,
  MAX_EXAMPLES,
  MIXED_CONTENT_CHECK,
  MIXED_CONTENT_WEIGHT,
  parseSrcset,
  Status,
} from "../src/index.js";

const PAGE = "https://app.test/shop/index.html";

function urls(html: string, page = PAGE): string[] {
  return findMixedContent(html, page).map((r) => r.url);
}

describe("parseSrcset", () => {
  it("returns each candidate URL without descriptors", () => {
    expect(parseSrcset("a.jpg 1x, http://x.test/b.jpg 2x,c.jpg")).toEqual([
      "a.jpg",
      "http://x.test/b.jpg",
      "c.jpg",
    ]);
  });

  it("keeps commas that are part of a URL when not followed by whitespace", () => {
    expect(parseSrcset("img.jpg?w=1,2 100w, b.jpg 200w")).toEqual(["img.jpg?w=1,2", "b.jpg"]);
  });

  it("handles empty and whitespace-only values", () => {
    expect(parseSrcset("")).toEqual([]);
    expect(parseSrcset("   ")).toEqual([]);
  });
});

describe("cssUrls", () => {
  it("finds url() with any quoting and @import", () => {
    const css = `a{background:url(http://a.test/1.png)} b{background:url( "http://a.test/2.png" )}
      c{background:url('/3.png')} @import "http://a.test/x.css"; @import url(http://a.test/y.css);`;
    expect(cssUrls(css)).toEqual([
      "http://a.test/1.png",
      "http://a.test/2.png",
      "/3.png",
      "http://a.test/y.css",
      "http://a.test/x.css",
    ]);
  });

  it("returns nothing for CSS without URLs", () => {
    expect(cssUrls("body { color: red }")).toEqual([]);
  });
});

describe("extractResources", () => {
  it("classifies each element by how browsers treat it", () => {
    const { references } = extractResources(`
      <script src="a.js"></script>
      <link rel="stylesheet" href="a.css">
      <link rel="canonical" href="http://app.test/">
      <iframe src="f.html"></iframe>
      <img src="i.png" srcset="i2.png 2x">
      <video src="v.mp4" poster="p.png"><source src="s.webm"></video>
      <form action="/login"><button formaction="/alt">go</button></form>
      <object data="o.swf"></object><embed src="e.swf">
      <input type="image" src="btn.png">
    `);
    expect(references.map((r) => [r.tag, r.attribute, r.value, r.kind])).toEqual([
      ["script", "src", "a.js", "blockable"],
      ["link", "href", "a.css", "blockable"],
      ["iframe", "src", "f.html", "blockable"],
      ["img", "src", "i.png", "upgradeable"],
      ["img", "srcset", "i2.png", "upgradeable"],
      ["video", "src", "v.mp4", "upgradeable"],
      ["video", "poster", "p.png", "upgradeable"],
      ["source", "src", "s.webm", "upgradeable"],
      ["form", "action", "/login", "form"],
      ["button", "formaction", "/alt", "form"],
      ["object", "data", "o.swf", "blockable"],
      ["embed", "src", "e.swf", "blockable"],
      ["input", "src", "btn.png", "blockable"],
    ]);
  });

  it("ignores non-fetching <link> rels like canonical and alternate", () => {
    const { references } = extractResources(
      '<link rel="canonical" href="http://x.test/"><link rel="alternate" href="http://x.test/feed">',
    );
    expect(references).toEqual([]);
  });

  it("matches rel tokens case-insensitively", () => {
    const { references } = extractResources('<LINK REL="Preload StyleSheet" HREF="x.css">');
    expect(references).toHaveLength(1);
  });

  it("does not report URLs inside comments or script text", () => {
    const html = `<!-- <script src="http://x.test/old.js"></script> -->
      <script>var s = '<script src="http://x.test/inline.js"><\\/script>';</script>`;
    expect(extractResources(html).references).toEqual([]);
  });

  it("decodes entities in attributes like a browser would", () => {
    const { references } = extractResources('<script src="&#104;ttp://x.test/a.js"></script>');
    expect(references[0]?.value).toBe("http://x.test/a.js");
  });

  it("collects CSS URLs from <style> blocks and style attributes", () => {
    const { references } = extractResources(
      '<style>.a{background:url(http://x.test/bg.png)}</style><div style="background:url(http://x.test/d.png)"></div>',
    );
    expect(references.map((r) => [r.tag, r.attribute, r.value])).toEqual([
      ["style", "css", "http://x.test/bg.png"],
      ["div", "style", "http://x.test/d.png"],
    ]);
  });

  it("records the first <base href> and meta CSP policies", () => {
    const out = extractResources(`<base href="/a/"><base href="/b/">
      <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">
      <meta http-equiv="refresh" content="5">`);
    expect(out.baseHref).toBe("/a/");
    expect(out.metaCsp).toEqual(["upgrade-insecure-requests"]);
  });

  it("skips empty attributes and survives malformed markup", () => {
    expect(extractResources('<script src="  "></script><img src=>').references).toEqual([]);
    expect(() => extractResources("<div><img src='a.png' <<<>>> </p>")).not.toThrow();
  });
});

describe("isPotentiallyTrustworthyHost", () => {
  it.each(["localhost", "LOCALHOST.", "dev.localhost", "127.0.0.1", "127.8.9.10", "[::1]"])(
    "%s is trustworthy over http",
    (host) => {
      expect(isPotentiallyTrustworthyHost(host)).toBe(true);
    },
  );

  it.each(["example.test", "localhost.evil.test", "10.0.0.1", "[::2]", "128.0.0.1"])(
    "%s is not",
    (host) => {
      expect(isPotentiallyTrustworthyHost(host)).toBe(false);
    },
  );
});

describe("findMixedContent", () => {
  it("returns only references that resolve to http:", () => {
    const html = `<script src="http://cdn.test/a.js"></script>
      <script src="https://cdn.test/b.js"></script>
      <script src="//cdn.test/c.js"></script>
      <script src="/d.js"></script>
      <img src="data:image/png;base64,AAAA">`;
    expect(urls(html)).toEqual(["http://cdn.test/a.js"]);
  });

  it("resolves relative URLs on an http page to http (no false positives for https pages)", () => {
    expect(urls('<script src="/d.js"></script>', "http://app.test/")).toEqual([
      "http://app.test/d.js",
    ]);
  });

  it("treats an http <base> as mixed content and resolves relative URLs against it", () => {
    const html = '<base href="http://static.test/assets/"><script src="app.js"></script>';
    expect(urls(html)).toEqual(["http://static.test/assets/", "http://static.test/assets/app.js"]);
  });

  it("ignores an unparseable <base> and falls back to the page URL", () => {
    expect(urls('<base href="http://[::1"><script src="x.js"></script>')).toEqual([]);
  });

  it("skips loopback and localhost references", () => {
    expect(urls('<script src="http://localhost:3000/hmr.js"></script>')).toEqual([]);
    expect(urls('<script src="http://127.0.0.1/x.js"></script>')).toEqual([]);
  });

  it("drops fragments and normalises the URL", () => {
    expect(urls('<iframe src="HTTP://CDN.test:80/f.html#top"></iframe>')).toEqual([
      "http://cdn.test/f.html",
    ]);
  });
});

describe("hasUpgradeInsecureRequests", () => {
  it("reads the enforced CSP header, including comma-joined policies", () => {
    const headers = new HeaderMap({
      "content-security-policy": "default-src 'self', upgrade-insecure-requests",
    });
    expect(hasUpgradeInsecureRequests(headers)).toBe(true);
  });

  it("ignores Content-Security-Policy-Report-Only", () => {
    const headers = new HeaderMap({
      "content-security-policy-report-only": "upgrade-insecure-requests",
    });
    expect(hasUpgradeInsecureRequests(headers)).toBe(false);
  });

  it("accepts a <meta> policy", () => {
    expect(hasUpgradeInsecureRequests(undefined, ["UPGRADE-INSECURE-REQUESTS"])).toBe(true);
    expect(hasUpgradeInsecureRequests(undefined, [])).toBe(false);
  });
});

describe("checkMixedContent", () => {
  it("is informational for http pages", () => {
    const { finding } = checkMixedContent({ pageUrl: "http://app.test/", html: "<p>" });
    expect(finding.status).toBe(Status.Info);
    expect(finding.weight).toBe(0);
  });

  it("is informational when the response was not HTML", () => {
    const { finding } = checkMixedContent({ pageUrl: PAGE, html: undefined });
    expect(finding.status).toBe(Status.Info);
    expect(finding.detail).toMatch(/not HTML/);
  });

  it("passes a clean https page", () => {
    const { finding, references } = checkMixedContent({
      pageUrl: PAGE,
      html: '<script src="/app.js"></script><img src="https://cdn.test/a.png">',
    });
    expect(finding).toMatchObject({
      check: MIXED_CONTENT_CHECK,
      status: Status.Pass,
      score: MIXED_CONTENT_WEIGHT,
      weight: MIXED_CONTENT_WEIGHT,
    });
    expect(references).toEqual([]);
  });

  it("fails on an insecure script", () => {
    const { finding, references } = checkMixedContent({
      pageUrl: PAGE,
      html: '<script src="http://cdn.test/lib.js"></script>',
    });
    expect(finding.status).toBe(Status.Fail);
    expect(finding.score).toBe(0);
    expect(finding.detail).toContain("Active mixed content: <script src> http://cdn.test/lib.js");
    expect(finding.recommendation).toMatch(/upgrade-insecure-requests/);
    expect(references).toHaveLength(1);
  });

  it("warns (not fails) when only upgradeable images are insecure", () => {
    const { finding } = checkMixedContent({
      pageUrl: PAGE,
      html: '<img src="http://cdn.test/a.png">',
    });
    expect(finding.status).toBe(Status.Warn);
    expect(finding.score).toBe(10);
    expect(finding.detail).toMatch(/auto-upgrade/);
  });

  it("fails on a form that submits over http", () => {
    const { finding } = checkMixedContent({
      pageUrl: PAGE,
      html: '<form action="http://app.test/login" method="post"></form>',
    });
    expect(finding.status).toBe(Status.Fail);
    expect(finding.detail).toMatch(/^Insecure form target/);
  });

  it("downgrades blockable content to a warning when upgrade-insecure-requests is set", () => {
    const { finding, upgradeInsecureRequests } = checkMixedContent({
      pageUrl: PAGE,
      html: '<script src="http://cdn.test/lib.js"></script>',
      headers: new HeaderMap({ "content-security-policy": "upgrade-insecure-requests" }),
    });
    expect(upgradeInsecureRequests).toBe(true);
    expect(finding.status).toBe(Status.Warn);
    expect(finding.detail).toMatch(/upgraded by upgrade-insecure-requests/);
  });

  it("honours upgrade-insecure-requests from a <meta> tag", () => {
    const { finding } = checkMixedContent({
      pageUrl: PAGE,
      html: `<meta http-equiv="content-security-policy" content="upgrade-insecure-requests">
        <script src="http://cdn.test/lib.js"></script>`,
    });
    expect(finding.status).toBe(Status.Warn);
  });

  it("still fails a cross-host http form even with upgrade-insecure-requests", () => {
    const headers = new HeaderMap({ "content-security-policy": "upgrade-insecure-requests" });
    const same = checkMixedContent({
      pageUrl: PAGE,
      html: '<form action="http://app.test/login"></form>',
      headers,
    });
    const cross = checkMixedContent({
      pageUrl: PAGE,
      html: '<form action="http://collector.test/login"></form>',
      headers,
    });
    expect(same.finding.status).toBe(Status.Warn);
    expect(cross.finding.status).toBe(Status.Fail);
  });

  it(`lists at most ${String(MAX_EXAMPLES)} examples and counts the rest`, () => {
    const html = Array.from(
      { length: 8 },
      (_, i) => `<script src="http://cdn.test/${String(i)}.js"></script>`,
    ).join("");
    const { finding, references } = checkMixedContent({ pageUrl: PAGE, html });
    expect(references).toHaveLength(8);
    expect(finding.detail).toContain("http://cdn.test/4.js; and 3 more");
    expect(finding.detail).not.toContain("http://cdn.test/5.js");
  });

  it("says so when the body was truncated", () => {
    const { finding } = checkMixedContent({ pageUrl: PAGE, html: "<p>", truncated: true });
    expect(finding.status).toBe(Status.Pass);
    expect(finding.detail).toMatch(/only the first part/);
  });
});
