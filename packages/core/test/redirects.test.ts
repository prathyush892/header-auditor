/** Pure tests for the redirect-chain and HTTP→HTTPS redirect analysis. */
import { describe, expect, it } from "vitest";
import {
  analyzeHttpsRedirect,
  checkRedirectChain,
  findDowngrades,
  HTTPS_REDIRECT_CHECK,
  HTTPS_REDIRECT_WEIGHT,
  REDIRECT_CHAIN_WEIGHT,
  Status,
  type HttpObservation,
  type RedirectHop,
} from "../src/index.js";

const HTTP = new URL("http://app.test/");

function hop(url: string, location: string, statusCode = 301): RedirectHop {
  return { url, statusCode, location };
}

function response(redirects: RedirectHop[], statusCode = 200): HttpObservation {
  const last = redirects.at(-1);
  return { kind: "response", redirects, finalUrl: last?.location ?? HTTP.href, statusCode };
}

describe("findDowngrades / checkRedirectChain", () => {
  it("is informational without redirects", () => {
    const f = checkRedirectChain([]);
    expect(f.status).toBe(Status.Info);
    expect(f.weight).toBe(0);
  });

  it("passes a chain that stays on or upgrades to https", () => {
    const f = checkRedirectChain([
      hop("http://app.test/", "https://app.test/"),
      hop("https://app.test/", "https://www.app.test/"),
    ]);
    expect(f).toMatchObject({ status: Status.Pass, score: REDIRECT_CHAIN_WEIGHT });
    expect(f.detail).toMatch(/^2 redirect\(s\)/);
  });

  it("fails an https → http hop and names it", () => {
    const chain = [
      hop("https://app.test/", "https://app.test/login"),
      hop("https://app.test/login", "http://sso.test/start", 302),
    ];
    expect(findDowngrades(chain)).toEqual([chain[1]]);
    const f = checkRedirectChain(chain);
    expect(f.status).toBe(Status.Fail);
    expect(f.score).toBe(0);
    expect(f.detail).toContain("https://app.test/login → http://sso.test/start");
  });

  it("does not count http → http as a downgrade", () => {
    expect(findDowngrades([hop("http://a.test/", "http://b.test/")])).toEqual([]);
  });
});

describe("analyzeHttpsRedirect", () => {
  it("passes a permanent same-host redirect to https", () => {
    for (const status of [301, 308]) {
      const f = analyzeHttpsRedirect(
        HTTP,
        response([hop("http://app.test/", "https://app.test/", status)]),
      );
      expect(f).toMatchObject({
        check: HTTPS_REDIRECT_CHECK,
        status: Status.Pass,
        score: HTTPS_REDIRECT_WEIGHT,
      });
    }
  });

  it("warns on a temporary redirect", () => {
    for (const status of [302, 303, 307]) {
      const f = analyzeHttpsRedirect(
        HTTP,
        response([hop("http://app.test/", "https://app.test/", status)]),
      );
      expect(f.status).toBe(Status.Warn);
      expect(f.score).toBe(10);
      expect(f.detail).toContain(`temporary ${String(status)}`);
    }
  });

  it("warns when the first hop upgrades to a different host", () => {
    const f = analyzeHttpsRedirect(
      HTTP,
      response([hop("http://app.test/", "https://www.app.test/")]),
    );
    expect(f.status).toBe(Status.Warn);
    expect(f.detail).toMatch(/different host \(www\.app\.test\)/);
  });

  it("warns when https is reached only after extra plain-http hops", () => {
    const f = analyzeHttpsRedirect(
      HTTP,
      response([
        hop("http://app.test/", "http://www.app.test/"),
        hop("http://www.app.test/", "https://www.app.test/"),
      ]),
    );
    expect(f.status).toBe(Status.Warn);
    expect(f.detail).toMatch(/after 1 more plain-HTTP redirect/);
  });

  it("fails when http serves the page directly", () => {
    const f = analyzeHttpsRedirect(HTTP, response([], 200));
    expect(f.status).toBe(Status.Fail);
    expect(f.score).toBe(0);
    expect(f.detail).toContain("answers 200 over plain HTTP");
    expect(f.recommendation).toMatch(/301/);
  });

  it("fails when redirects never reach https", () => {
    const f = analyzeHttpsRedirect(
      HTTP,
      response([hop("http://app.test/", "http://app.test/home")]),
    );
    expect(f.status).toBe(Status.Fail);
    expect(f.detail).toMatch(/never reached HTTPS/);
  });

  it("fails when the chain goes back to http after upgrading", () => {
    const f = analyzeHttpsRedirect(
      HTTP,
      response([
        hop("http://app.test/", "https://app.test/"),
        hop("https://app.test/", "http://app.test/legacy", 302),
      ]),
    );
    expect(f.status).toBe(Status.Fail);
    expect(f.detail).toMatch(/goes back to HTTP/);
  });

  it("is informational when nothing listens on http", () => {
    const f = analyzeHttpsRedirect(HTTP, {
      kind: "error",
      redirects: [],
      code: "NETWORK",
      failedUrl: HTTP.href,
    });
    expect(f.status).toBe(Status.Info);
    expect(f.weight).toBe(0);
    expect(f.detail).toContain("(NETWORK)");
  });

  it("caps the score when the https side fails after a good redirect", () => {
    const f = analyzeHttpsRedirect(HTTP, {
      kind: "error",
      redirects: [hop("http://app.test/", "https://app.test/")],
      code: "TLS_ERROR",
      failedUrl: "https://app.test/",
    });
    expect(f.status).toBe(Status.Warn);
    expect(f.score).toBe(8);
    expect(f.detail).toMatch(/HTTPS request then failed \(TLS_ERROR at https:\/\/app\.test\/\)/);
  });

  it("keeps a lower score when the error follows an already-weak redirect", () => {
    const f = analyzeHttpsRedirect(HTTP, {
      kind: "error",
      redirects: [hop("http://app.test/", "https://app.test/", 302)],
      code: "TIMEOUT",
      failedUrl: "https://app.test/",
    });
    expect(f.score).toBe(8);
    expect(f.recommendation).toMatch(/301 or 308/);
  });
});
