/**
 * Integration tests for scanUrl() against a local mock server bound to
 * 127.0.0.1. No test sends traffic anywhere else: every "private" or
 * "internal" target below is rejected before a socket is opened, and the
 * server's request counter proves it.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  scanUrl,
  ScanError,
  type Resolver,
  type ScanErrorCode,
  type ScanOptions,
} from "../src/index.js";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

const routes = new Map<string, Handler>();
const hits: string[] = [];
let server: Server;
let base: string;
let port: number;

const LOCAL_ONLY: ScanOptions = { allowAddresses: ["127.0.0.1"] };

/** Resolves every name in `table`; anything else fails like NXDOMAIN. */
function fixtureResolver(table: Record<string, string[]>): Resolver {
  return (hostname) => {
    const addresses = new Map(Object.entries(table)).get(hostname);
    if (!addresses) return Promise.reject(new Error(`ENOTFOUND ${hostname}`));
    return Promise.resolve(
      addresses.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })),
    );
  };
}

function redirect(status: number, location: string): Handler {
  return (_req, res) => {
    res.writeHead(status, { location }).end();
  };
}

async function expectScanError(promise: Promise<unknown>, code: ScanErrorCode): Promise<ScanError> {
  const err: unknown = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(ScanError);
  expect((err as ScanError).code).toBe(code);
  return err as ScanError;
}

beforeAll(async () => {
  server = createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://placeholder").pathname;
    hits.push(`${req.headers.host ?? ""}${path}`);
    const handler = routes.get(path);
    if (handler) handler(req, res);
    else res.writeHead(404, { "content-type": "text/plain" }).end("not found");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as AddressInfo).port;
  base = `http://127.0.0.1:${String(port)}`;

  routes.set("/secure", (_req, res) => {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Set-Cookie", [
      "a=1; HttpOnly; SameSite=Lax",
      "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly; SameSite=Strict",
    ]);
    res.writeHead(200, { "content-type": "text/html" }).end("<!doctype html><p>ok</p>");
  });
  routes.set("/bare", (_req, res) => {
    res.writeHead(200, { server: "nginx/1.25.3", "x-powered-by": "Express" }).end("hi");
  });
  routes.set("/error", (_req, res) => {
    res.writeHead(500, { "x-content-type-options": "nosniff" }).end("boom");
  });
  routes.set("/big", (_req, res) => {
    res.writeHead(200).end("x".repeat(1024 * 1024));
  });
  routes.set("/hang", () => {
    /* never responds */
  });
  routes.set("/hop1", redirect(301, "/hop2"));
  routes.set("/hop2", redirect(302, "hop3?x=1"));
  routes.set("/hop3", redirect(307, `${base}/bare`));
  routes.set("/loop-a", redirect(302, "/loop-b"));
  routes.set("/loop-b", redirect(302, "/loop-a"));
  for (let i = 0; i < 10; i++)
    routes.set(`/chain/${String(i)}`, redirect(302, `/chain/${String(i + 1)}`));
  routes.set("/to-private", redirect(302, "http://10.0.0.1/admin"));
  routes.set("/to-metadata", redirect(302, "http://169.254.169.254/latest/meta-data/"));
  routes.set("/to-internal-name", redirect(302, `http://internal.test:${String(port)}/bare`));
  routes.set("/to-file", redirect(302, "file:///etc/passwd"));
  routes.set("/to-creds", redirect(302, `http://user:pw@127.0.0.1:${String(port)}/bare`));
  routes.set("/to-bad-location", redirect(302, "http://[::1"));
  routes.set("/redirect-no-location", (_req, res) => {
    res.writeHead(302).end();
  });
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) =>
    server.close(() => {
      resolve();
    }),
  );
});

beforeEach(() => {
  hits.length = 0;
});

describe("scanUrl: fetching and grading", () => {
  it("grades the response headers of a local server", async () => {
    const { report, redirects } = await scanUrl(`${base}/secure`, LOCAL_ONLY);
    expect(redirects).toEqual([]);
    expect(report.url).toBe(`${base}/secure`);
    expect(report.statusCode).toBe(200);
    const byCheck = new Map(report.findings.map((f) => [f.check, f.status]));
    expect(byCheck.get("Content-Security-Policy")).toBe("pass");
    expect(byCheck.get("X-Content-Type-Options")).toBe("pass");
    expect(byCheck.get("Strict-Transport-Security")).toBe("info"); // not HTTPS
    expect(report.grade).toBe("A");
  });

  it("keeps each Set-Cookie line separate (dates contain commas)", async () => {
    const { report } = await scanUrl(`${base}/secure`, LOCAL_ONLY);
    const cookies = report.findings.find((f) => f.check === "Cookie flags");
    expect(cookies?.detail).not.toMatch(/GMT/);
    expect(cookies?.status).toBe("pass");
    expect(cookies?.detail).toMatch(/2 cookie/);
  });

  it("grades a bare response as F and flags disclosure headers", async () => {
    const { report } = await scanUrl(`${base}/bare`, LOCAL_ONLY);
    expect(report.grade).toBe("F");
    expect(report.findings.find((f) => f.check === "Information disclosure")?.status).toBe("warn");
  });

  it("still grades 5xx responses (error pages carry headers too)", async () => {
    const { report } = await scanUrl(`${base}/error`, LOCAL_ONLY);
    expect(report.statusCode).toBe(500);
  });

  it("drains large bodies without failing", async () => {
    const { report } = await scanUrl(`${base}/big`, LOCAL_ONLY);
    expect(report.statusCode).toBe(200);
  });

  it("sends the configured User-Agent", async () => {
    let seen: string | undefined;
    routes.set("/ua", (req, res) => {
      seen = req.headers["user-agent"];
      res.writeHead(204).end();
    });
    await scanUrl(`${base}/ua`, { ...LOCAL_ONLY, userAgent: "test-agent/1.0" });
    expect(seen).toBe("test-agent/1.0");
  });

  it("connects through the injected resolver (host name kept in Host header)", async () => {
    const resolver = fixtureResolver({ "scanner.test": ["127.0.0.1"] });
    const { report } = await scanUrl(`http://scanner.test:${String(port)}/bare`, {
      ...LOCAL_ONLY,
      resolver,
    });
    expect(report.url).toBe(`http://scanner.test:${String(port)}/bare`);
    expect(hits).toEqual([`scanner.test:${String(port)}/bare`]);
  });
});

describe("scanUrl: SSRF guard", () => {
  it("blocks loopback by default, before any request is sent", async () => {
    await expectScanError(scanUrl(`${base}/bare`), "BLOCKED_ADDRESS");
    await expectScanError(scanUrl(`http://[::1]:${String(port)}/bare`), "BLOCKED_ADDRESS");
    expect(hits).toEqual([]);
  });

  it("blocks host names that resolve to private addresses", async () => {
    const resolver = fixtureResolver({ "localhost.test": ["127.0.0.1"] });
    const err = await expectScanError(
      scanUrl(`http://localhost.test:${String(port)}/bare`, { resolver }),
      "BLOCKED_ADDRESS",
    );
    expect(err.message).toContain("127.0.0.1");
    expect(hits).toEqual([]);
  });

  it("blocks a host if any of its records is private, even with one allowed", async () => {
    const resolver = fixtureResolver({ "mixed.test": ["127.0.0.1", "10.0.0.9"] });
    await expectScanError(
      scanUrl(`http://mixed.test:${String(port)}/bare`, { ...LOCAL_ONLY, resolver }),
      "BLOCKED_ADDRESS",
    );
    expect(hits).toEqual([]);
  });

  it("allowPrivate opens private targets for local development", async () => {
    const { report } = await scanUrl(`${base}/bare`, { allowPrivate: true });
    expect(report.statusCode).toBe(200);
  });

  it.each([
    ["/to-private", "BLOCKED_ADDRESS"],
    ["/to-metadata", "BLOCKED_ADDRESS"],
    ["/to-file", "BLOCKED_SCHEME"],
    ["/to-creds", "INVALID_URL"],
    ["/to-bad-location", "INVALID_URL"],
  ] as const)("re-validates redirect targets: %s → %s", async (path, code) => {
    await expectScanError(scanUrl(`${base}${path}`, LOCAL_ONLY), code);
    expect(hits).toEqual([`127.0.0.1:${String(port)}${path}`]);
  });

  it("re-checks DNS on redirects to a new host name", async () => {
    const resolver = fixtureResolver({ "internal.test": ["192.168.0.10"] });
    await expectScanError(
      scanUrl(`${base}/to-internal-name`, { ...LOCAL_ONLY, resolver }),
      "BLOCKED_ADDRESS",
    );
    expect(hits).toEqual([`127.0.0.1:${String(port)}/to-internal-name`]);
  });
});

describe("scanUrl: redirects", () => {
  it("follows absolute and relative redirects and records the chain", async () => {
    const { report, redirects } = await scanUrl(`${base}/hop1`, LOCAL_ONLY);
    expect(report.url).toBe(`${base}/bare`);
    expect(redirects).toEqual([
      { url: `${base}/hop1`, statusCode: 301, location: `${base}/hop2` },
      { url: `${base}/hop2`, statusCode: 302, location: `${base}/hop3?x=1` },
      { url: `${base}/hop3?x=1`, statusCode: 307, location: `${base}/bare` },
    ]);
  });

  it("grades the redirect itself when followRedirects is false", async () => {
    const { report, redirects } = await scanUrl(`${base}/hop1`, {
      ...LOCAL_ONLY,
      followRedirects: false,
    });
    expect(report.statusCode).toBe(301);
    expect(redirects).toEqual([]);
    expect(hits).toHaveLength(1);
  });

  it("treats a 3xx without Location as the final response", async () => {
    const { report } = await scanUrl(`${base}/redirect-no-location`, LOCAL_ONLY);
    expect(report.statusCode).toBe(302);
  });

  it("detects redirect loops", async () => {
    await expectScanError(scanUrl(`${base}/loop-a`, LOCAL_ONLY), "REDIRECT_LOOP");
    expect(hits).toHaveLength(2);
  });

  it("stops after maxRedirects", async () => {
    await expectScanError(
      scanUrl(`${base}/chain/0`, { ...LOCAL_ONLY, maxRedirects: 3 }),
      "TOO_MANY_REDIRECTS",
    );
    expect(hits).toHaveLength(4);
  });

  it("maxRedirects 0 fails on the first redirect", async () => {
    await expectScanError(
      scanUrl(`${base}/hop1`, { ...LOCAL_ONLY, maxRedirects: 0 }),
      "TOO_MANY_REDIRECTS",
    );
  });
});

describe("scanUrl: timeouts, cancellation and failures", () => {
  it("times out a server that never answers", async () => {
    const started = Date.now();
    await expectScanError(scanUrl(`${base}/hang`, { ...LOCAL_ONLY, timeoutMs: 200 }), "TIMEOUT");
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("honours an external AbortSignal", async () => {
    const controller = new AbortController();
    const pending = scanUrl(`${base}/hang`, { ...LOCAL_ONLY, signal: controller.signal });
    setTimeout(() => {
      controller.abort();
    }, 50);
    await expectScanError(pending, "ABORTED");
  });

  it("reports DNS failures", async () => {
    const resolver = fixtureResolver({ "empty.test": [] });
    await expectScanError(scanUrl("http://nxdomain.test/", { resolver }), "DNS_FAILURE");
    await expectScanError(scanUrl("http://empty.test/", { resolver }), "DNS_FAILURE");
  });

  it("reports connection refused as a network error", async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
    const closedPort = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) =>
      closed.close(() => {
        resolve();
      }),
    );
    await expectScanError(
      scanUrl(`http://127.0.0.1:${String(closedPort)}/`, LOCAL_ONLY),
      "NETWORK",
    );
  });
});

describe("scanUrl: input validation", () => {
  it.each([
    ["not a url", {}, "INVALID_URL"],
    ["ftp://127.0.0.1/", {}, "BLOCKED_SCHEME"],
    ["http://u:p@example.com/", {}, "INVALID_URL"],
    ["http://example.com/", { timeoutMs: 0 }, "INVALID_OPTIONS"],
    ["http://example.com/", { timeoutMs: 1.5 }, "INVALID_OPTIONS"],
    ["http://example.com/", { timeoutMs: 999_999 }, "INVALID_OPTIONS"],
    ["http://example.com/", { maxRedirects: -1 }, "INVALID_OPTIONS"],
    ["http://example.com/", { maxRedirects: 21 }, "INVALID_OPTIONS"],
    ["http://example.com/", { userAgent: "" }, "INVALID_OPTIONS"],
    ["http://example.com/", { userAgent: "a\r\nX-Injected: 1" }, "INVALID_OPTIONS"],
    ["http://example.com/", { allowAddresses: ["not-an-ip"] }, "INVALID_OPTIONS"],
  ] as const)("%s with %j → %s", async (url, options: ScanOptions, code) => {
    await expectScanError(scanUrl(url, options), code);
  });
});
