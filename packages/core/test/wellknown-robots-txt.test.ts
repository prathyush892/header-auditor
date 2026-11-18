import { describe, expect, it } from "vitest";
import {
  checkRobotsTxt,
  classifyPath,
  findSensitivePaths,
  MAX_ROBOTS_EXAMPLES,
  MAX_ROBOTS_RULES,
  parseRobotsTxt,
  pathSegments,
  ROBOTS_TXT_PATH,
  ROBOTS_TXT_WEIGHT,
  Status,
  type WellKnownObservation,
} from "../src/index.js";

const URL_ROBOTS = `https://example.test${ROBOTS_TXT_PATH}`;

function found(text: string, truncated = false): WellKnownObservation {
  return {
    kind: "found",
    url: URL_ROBOTS,
    path: ROBOTS_TXT_PATH,
    finalUrl: URL_ROBOTS,
    statusCode: 200,
    mediaType: "text/plain",
    text,
    truncated,
    redirects: [],
  };
}

describe("parseRobotsTxt", () => {
  it("groups consecutive user-agent lines and attaches rules to the group", () => {
    const parsed = parseRobotsTxt(
      [
        "User-agent: GoogleBot",
        "User-agent: bingbot",
        "Disallow: /private/ # trailing comment",
        "Allow: /private/public.html",
        "",
        "User-agent: *",
        "Disallow: /tmp/",
        "Sitemap: https://example.test/sitemap.xml",
      ].join("\r\n"),
    );
    expect(parsed.rules.map((r) => [r.kind, r.path, r.userAgents, r.line])).toEqual([
      ["disallow", "/private/", ["googlebot", "bingbot"], 3],
      ["allow", "/private/public.html", ["googlebot", "bingbot"], 4],
      ["disallow", "/tmp/", ["*"], 7],
    ]);
    expect(parsed.sitemaps).toEqual(["https://example.test/sitemap.xml"]);
  });

  it("ignores comments, unknown keys, empty Disallow and lines without a colon", () => {
    const parsed = parseRobotsTxt(
      "# Disallow: /secret\nCrawl-delay: 5\nDisallow:\nnonsense\nDISALLOW: /admin",
    );
    expect(parsed.rules.map((r) => r.path)).toEqual(["/admin"]);
    expect(parsed.rules[0]?.userAgents).toEqual(["*"]);
  });

  it("strips a byte-order mark", () => {
    expect(parseRobotsTxt("﻿Disallow: /x").rules).toHaveLength(1);
  });

  it("caps the rules it keeps", () => {
    const text = Array.from(
      { length: MAX_ROBOTS_RULES + 7 },
      (_, i) => `Disallow: /p${String(i)}`,
    ).join("\n");
    const parsed = parseRobotsTxt(text);
    expect(parsed.rules).toHaveLength(MAX_ROBOTS_RULES);
    expect(parsed.droppedRules).toBe(7);
  });
});

describe("pathSegments", () => {
  it("lower-cases, drops wildcards, the query and empty segments, and decodes escapes", () => {
    expect(pathSegments("/Admin/*/Panel$?x=1")).toEqual(["admin", "panel"]);
    expect(pathSegments("/%2Egit/")).toEqual([".git"]);
    expect(pathSegments("/bad%zz/")).toEqual(["bad%zz"]);
  });
});

describe("classifyPath", () => {
  it.each([
    ["/.git/", "source-control", "high"],
    ["/.svn/entries", "source-control", "high"],
    ["/.env", "secrets-config", "high"],
    ["/.env.production", "secrets-config", "high"],
    ["/wp-config.php", "secrets-config", "high"],
    ["/keys/server.pem", "secrets-config", "high"],
    ["/backup/", "backup-dump", "high"],
    ["/*.sql$", "backup-dump", "high"],
    ["/index.php.bak", "backup-dump", "high"],
    ["/wp-admin/", "framework-default", "low"],
    ["/admin/", "admin-interface", "medium"],
    ["/phpMyAdmin/", "admin-interface", "medium"],
    ["/admin.php", "admin-interface", "medium"],
    ["/install/", "installer", "medium"],
    ["/logs/", "logs", "medium"],
    ["/app/error.log", "logs", "medium"],
    ["/staging/", "non-production", "medium"],
    ["/internal/reports", "internal", "medium"],
  ])("%s is %s (%s)", (path, category, level) => {
    expect(classifyPath(path)).toEqual({ category, level });
  });

  it.each([
    "/",
    "/search",
    "/cart/",
    "/administration-guide",
    "/blog/backups-explained",
    "/downloads/*.zip$",
    "/cgi-bin/",
    "/sitemap.xml.gz",
  ])("%s is not sensitive", (path) => {
    expect(classifyPath(path)).toBeUndefined();
  });

  it("classifies by the most severe matching category", () => {
    expect(classifyPath("/admin/backup.sql")?.category).toBe("backup-dump");
  });
});

describe("findSensitivePaths", () => {
  it("keeps allow and disallow rules and de-duplicates by path", () => {
    const { rules } = parseRobotsTxt(
      "User-agent: a\nDisallow: /admin/\nUser-agent: b\nDisallow: /admin/\nAllow: /.git/\nDisallow: /shop/",
    );
    expect(findSensitivePaths(rules).map((p) => [p.path, p.kind, p.line])).toEqual([
      ["/admin/", "disallow", 2],
      ["/.git/", "allow", 5],
    ]);
  });
});

describe("checkRobotsTxt", () => {
  it("passes when nothing sensitive is listed", () => {
    const f = checkRobotsTxt(found("User-agent: *\nDisallow: /search\nDisallow: /cart/"));
    expect(f.status).toBe(Status.Pass);
    expect(f.score).toBe(ROBOTS_TXT_WEIGHT);
    expect(f.detail).toContain("2 rule(s)");
  });

  it("passes framework defaults but mentions them", () => {
    const f = checkRobotsTxt(
      found("User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php"),
    );
    expect(f.status).toBe(Status.Pass);
    expect(f.detail).toContain("Framework defaults only");
  });

  it("warns (7) on medium-risk paths", () => {
    const f = checkRobotsTxt(found("User-agent: *\nDisallow: /admin/\nDisallow: /staging/"));
    expect(f.status).toBe(Status.Warn);
    expect(f.score).toBe(7);
    expect(f.detail).toContain("/admin/ (admin-interface)");
    expect(f.recommendation).toContain("does not restrict access");
  });

  it("warns (3) when any high-risk path is listed", () => {
    const f = checkRobotsTxt(found("User-agent: *\nDisallow: /admin/\nDisallow: /db/backup.sql"));
    expect(f.status).toBe(Status.Warn);
    expect(f.score).toBe(3);
  });

  it("limits the examples in the detail", () => {
    const text = Array.from(
      { length: MAX_ROBOTS_EXAMPLES + 3 },
      (_, i) => `Disallow: /admin${String(i)}/admin`,
    ).join("\n");
    expect(checkRobotsTxt(found(text)).detail).toContain("and 3 more");
  });

  it("notes truncation and dropped rules", () => {
    const text = Array.from(
      { length: MAX_ROBOTS_RULES + 1 },
      (_, i) => `Disallow: /p${String(i)}`,
    ).join("\n");
    const f = checkRobotsTxt(found(text, true));
    expect(f.detail).toContain("(+1 not analysed)");
    expect(f.detail).toContain("file truncated");
  });

  it("passes when there is no robots.txt", () => {
    const f = checkRobotsTxt({
      kind: "missing",
      url: URL_ROBOTS,
      path: ROBOTS_TXT_PATH,
      statusCode: 404,
      reason: "HTTP 404",
    });
    expect(f.status).toBe(Status.Pass);
    expect(f.detail).toContain("no paths advertised");
  });

  it("is unscored info when it couldn't be fetched", () => {
    const f = checkRobotsTxt({
      kind: "error",
      url: URL_ROBOTS,
      path: ROBOTS_TXT_PATH,
      code: "NETWORK",
    });
    expect(f.status).toBe(Status.Info);
    expect(f.weight).toBe(0);
  });
});
