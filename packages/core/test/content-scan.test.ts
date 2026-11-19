/**
 * Integration tests for the content checks over real sockets: scanUrl()'s
 * bounded HTML read + content report, and probeHttpsRedirect(). Servers listen
 * on 127.0.0.1 only; "app.test" is mapped there by an injected resolver, and
 * the https server uses a certificate minted at test time. The http:// URLs
 * inside the fixture HTML are never requested.
 */
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  httpVariant,
  isHtmlResponse,
  parseContentType,
  probeHttpsRedirect,
  scanUrl,
  ScanError,
  Status,
  type HttpsRedirectOptions,
  type Resolver,
  type ScanErrorCode,
  type ScanOptions,
} from "../src/index.js";
import { TestPki } from "./helpers/pki.js";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

const pki = new TestPki();
const SRI_HASH = `sha384-${createHash("sha384").update("console.log(1)").digest("base64")}`;
/** Paths the https server saw, to prove the scanner never fetched subresources. */
const requestedPaths: string[] = [];
const httpRoutes = new Map<string, Handler>();
const httpsRoutes = new Map<string, Handler>();
const servers: Server[] = [];
let httpPort: number;
let httpsPort: number;
let closedPort: number;
let caCert: string;
let httpsBase: string;
let httpBase: string;

const resolver: Resolver = (hostname) =>
  hostname === "app.test"
    ? Promise.resolve([{ address: "127.0.0.1", family: 4 }])
    : Promise.reject(new Error(`ENOTFOUND ${hostname}`));

type LocalOptions = ScanOptions & HttpsRedirectOptions;

function local(extra: LocalOptions = {}): LocalOptions {
  return { allowAddresses: ["127.0.0.1"], resolver, ca: caCert, ...extra };
}

function router(routes: Map<string, Handler>): Handler {
  return (req, res) => {
    const path = new URL(req.url ?? "/", "http://placeholder").pathname;
    requestedPaths.push(path);
    const handler = routes.get(path);
    if (handler) handler(req, res);
    else res.writeHead(404, { "content-type": "text/plain" }).end("not found");
  };
}

function html(body: string, headers: Record<string, string> = {}): Handler {
  return (_req, res) => {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", ...headers }).end(body);
  };
}

function redirect(status: number, location: () => string): Handler {
  return (_req, res) => {
    res.writeHead(status, { location: location() }).end();
  };
}

async function listen(server: Server): Promise<number> {
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
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
  const ca = pki.createCa();
  caCert = ca.cert;
  const leaf = pki.issue({ commonName: "app.test", sans: ["DNS:app.test"], issuer: ca });

  httpPort = await listen(createServer(router(httpRoutes)));
  httpsPort = await listen(createHttpsServer(leaf, router(httpsRoutes)));
  const closed = createServer();
  await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
  closedPort = (closed.address() as AddressInfo).port;
  await new Promise<void>((resolve) =>
    closed.close(() => {
      resolve();
    }),
  );

  httpBase = `http://app.test:${String(httpPort)}`;
  httpsBase = `https://app.test:${String(httpsPort)}`;

  // https side
  httpsRoutes.set("/clean", html('<script src="/app.js"></script><img src="//cdn.test/a.png">'));
  httpsRoutes.set("/mixed", html('<script src="http://cdn.test/lib.js"></script>'));
  httpsRoutes.set(
    "/mixed-upgraded",
    html('<script src="http://cdn.test/lib.js"></script>', {
      "content-security-policy": "upgrade-insecure-requests",
    }),
  );
  httpsRoutes.set("/json", (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" }).end('{"a":"http://x.test/"}');
  });
  httpsRoutes.set("/no-type", (_req, res) => {
    res.end('<script src="http://cdn.test/sniffed.js"></script>');
  });
  httpsRoutes.set("/huge", (_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.write('<p>start</p><script src="https://cdn.test/ok.js"></script>');
    // The insecure reference sits past the read limit, so it must not be seen.
    res.end(`${" ".repeat(64 * 1024)}<script src="http://cdn.test/late.js"></script>`);
  });
  httpsRoutes.set(
    "/downgrade",
    redirect(302, () => `${httpBase}/plain`),
  );
  httpsRoutes.set("/ok", html("<p>ok</p>"));
  httpsRoutes.set(
    "/sri",
    html(
      `<script src="https://cdn.test/pinned.js" integrity="${SRI_HASH}" crossorigin="anonymous"></script>` +
        '<script src="https://cdn.test/unpinned.js"></script>' +
        '<script src="https://static.app.test/own.js"></script>',
    ),
  );

  // http side
  httpRoutes.set("/plain", html('<script src="http://cdn.test/a.js"></script>'));
  httpRoutes.set(
    "/upgrade",
    redirect(301, () => `${httpsBase}/ok`),
  );
  httpRoutes.set(
    "/upgrade-308",
    redirect(308, () => `${httpsBase}/ok`),
  );
  httpRoutes.set(
    "/temp",
    redirect(302, () => `${httpsBase}/ok`),
  );
  httpRoutes.set(
    "/hop",
    redirect(301, () => `${httpBase}/upgrade`),
  );
  httpRoutes.set(
    "/broken-upgrade",
    redirect(301, () => `https://app.test:${String(closedPort)}/`),
  );
  httpRoutes.set(
    "/to-private",
    redirect(301, () => "https://10.0.0.1/"),
  );
});

afterAll(async () => {
  await Promise.all(
    servers.map(
      (s) =>
        new Promise<void>((resolve) => {
          s.closeAllConnections();
          s.close(() => {
            resolve();
          });
        }),
    ),
  );
  pki.cleanup();
});

describe("parseContentType / isHtmlResponse", () => {
  it("splits media type and charset, case-insensitively", () => {
    expect(parseContentType('Text/HTML; Charset="ISO-8859-1"')).toEqual({
      mediaType: "text/html",
      charset: "ISO-8859-1",
    });
    expect(parseContentType("text/html; boundary=x")).toEqual({
      mediaType: "text/html",
      charset: undefined,
    });
    expect(parseContentType(undefined)).toEqual({ mediaType: "", charset: undefined });
  });

  it("treats HTML, XHTML and a missing type as HTML", () => {
    expect(isHtmlResponse("text/html")).toBe(true);
    expect(isHtmlResponse("application/xhtml+xml; charset=utf-8")).toBe(true);
    expect(isHtmlResponse(undefined)).toBe(true);
    expect(isHtmlResponse("application/json")).toBe(false);
    expect(isHtmlResponse("text/plain")).toBe(false);
  });
});

describe("scanUrl content report", () => {
  it("passes a clean https page and does not change the header report", async () => {
    const { report, content } = await scanUrl(`${httpsBase}/clean`, local());
    expect(report.findings.map((f) => f.check)).not.toContain("Mixed content");
    expect(content.findings.map((f) => [f.check, f.status])).toEqual([
      ["Redirect chain", Status.Info],
      ["Mixed content", Status.Pass],
      ["Subresource Integrity", Status.Pass],
    ]);
    expect(content.score).toBe(100);
    expect(content.bodyBytes).toBeGreaterThan(0);
    expect(content.bodyTruncated).toBe(false);
  });

  it("grades third-party Subresource Integrity without fetching the scripts", async () => {
    requestedPaths.length = 0;
    const { content } = await scanUrl(`${httpsBase}/sri`, local());
    expect(content.subresourceIntegrity.map((r) => [r.url, r.status])).toEqual([
      ["https://cdn.test/pinned.js", "protected"],
      ["https://cdn.test/unpinned.js", "missing"],
    ]);
    expect(content.findings[2]?.status).toBe(Status.Fail);
    // Only the page itself was requested; cdn.test doesn't even resolve.
    expect(requestedPaths).toEqual(["/sri"]);
  });

  it("fails an https page that loads an http script", async () => {
    const { content } = await scanUrl(`${httpsBase}/mixed`, local());
    expect(content.mixedContent.map((r) => r.url)).toEqual(["http://cdn.test/lib.js"]);
    expect(content.findings[1]?.status).toBe(Status.Fail);
    expect(content.grade).toBe("F");
  });

  it("credits upgrade-insecure-requests from the response header", async () => {
    const { content } = await scanUrl(`${httpsBase}/mixed-upgraded`, local());
    expect(content.upgradeInsecureRequests).toBe(true);
    expect(content.findings[1]?.status).toBe(Status.Warn);
  });

  it("does not read non-HTML bodies", async () => {
    const { content } = await scanUrl(`${httpsBase}/json`, local());
    expect(content.bodyBytes).toBe(0);
    expect(content.findings[1]?.status).toBe(Status.Info);
  });

  it("reads a response without Content-Type as HTML, like a browser sniffing it", async () => {
    const { content } = await scanUrl(`${httpsBase}/no-type`, local());
    expect(content.mixedContent).toHaveLength(1);
  });

  it("stops reading at maxBodyBytes and reports the truncation", async () => {
    const { content } = await scanUrl(`${httpsBase}/huge`, local({ maxBodyBytes: 4096 }));
    expect(content.bodyBytes).toBe(4096);
    expect(content.bodyTruncated).toBe(true);
    expect(content.mixedContent).toEqual([]);
    expect(content.findings[1]?.detail).toMatch(/only the first part/);
  });

  it("sees the late reference when the limit is large enough", async () => {
    const { content } = await scanUrl(`${httpsBase}/huge`, local());
    expect(content.bodyTruncated).toBe(false);
    expect(content.mixedContent.map((r) => r.url)).toEqual(["http://cdn.test/late.js"]);
  });

  it("skips the body entirely with maxBodyBytes: 0", async () => {
    const { content } = await scanUrl(`${httpsBase}/mixed`, local({ maxBodyBytes: 0 }));
    expect(content.bodyBytes).toBe(0);
    expect(content.findings[1]?.status).toBe(Status.Info);
  });

  it("flags an https → http downgrade in the redirect chain", async () => {
    const { redirects, content, report } = await scanUrl(`${httpsBase}/downgrade`, local());
    expect(redirects).toHaveLength(1);
    expect(report.url).toBe(`${httpBase}/plain`);
    expect(content.findings[0]?.status).toBe(Status.Fail);
    // The final page is http, so mixed content is not applicable there.
    expect(content.findings[1]?.status).toBe(Status.Info);
  });

  it.each([-1, 1.5, 10 * 1024 * 1024 + 1, Number.NaN])(
    "rejects maxBodyBytes=%s before connecting",
    async (maxBodyBytes) => {
      await expectScanError(scanUrl(`${httpsBase}/ok`, local({ maxBodyBytes })), "INVALID_OPTIONS");
    },
  );

  it("attaches the redirects followed before a failure to the ScanError", async () => {
    const err = await expectScanError(scanUrl(`${httpBase}/broken-upgrade`, local()), "NETWORK");
    expect(err.url).toBe(`https://app.test:${String(closedPort)}/`);
    expect(err.redirects).toEqual([
      {
        url: `${httpBase}/broken-upgrade`,
        statusCode: 301,
        location: `https://app.test:${String(closedPort)}/`,
      },
    ]);
  });
});

describe("httpVariant", () => {
  it("keeps host and path, drops the query, and uses port 80 for https targets", () => {
    expect(httpVariant("https://app.test:8443/a/b?x=1#f").href).toBe("http://app.test/a/b");
  });

  it("keeps an http target's own port and honours httpPort", () => {
    expect(httpVariant("http://app.test:8080/").href).toBe("http://app.test:8080/");
    expect(httpVariant("https://app.test/", 8081).href).toBe("http://app.test:8081/");
  });

  it.each([0, 65_536, 1.5])("rejects httpPort=%s", (port) => {
    expect(() => httpVariant("https://app.test/", port)).toThrow(ScanError);
  });

  it("rejects non-http(s) targets and embedded credentials", () => {
    expect(() => httpVariant("ftp://app.test/")).toThrow(/not allowed/);
    expect(() => httpVariant("https://u:p@app.test/")).toThrow(/credentials/);
  });
});

describe("probeHttpsRedirect", () => {
  it.each([
    ["/upgrade", 301],
    ["/upgrade-308", 308],
  ])("passes %s (permanent %s to https on the same host)", async (path, status) => {
    const result = await probeHttpsRedirect(`${httpsBase}${path}`, local({ httpPort }));
    expect(result.httpUrl).toBe(`${httpBase}${path}`);
    expect(result.finding.status).toBe(Status.Pass);
    expect(result.redirects[0]?.statusCode).toBe(status);
    expect(result.finalUrl).toBe(`${httpsBase}/ok`);
    expect(result.errorCode).toBeUndefined();
  });

  it("warns on a temporary redirect", async () => {
    const result = await probeHttpsRedirect(`${httpsBase}/temp`, local({ httpPort }));
    expect(result.finding.status).toBe(Status.Warn);
    expect(result.finding.detail).toMatch(/temporary 302/);
  });

  it("warns when an extra http hop comes first", async () => {
    const result = await probeHttpsRedirect(`${httpsBase}/hop`, local({ httpPort }));
    expect(result.redirects).toHaveLength(2);
    expect(result.finding.status).toBe(Status.Warn);
  });

  it("fails when plain http serves the page", async () => {
    const result = await probeHttpsRedirect(`${httpsBase}/plain`, local({ httpPort }));
    expect(result.finding.status).toBe(Status.Fail);
    expect(result.finding.detail).toContain("answers 200 over plain HTTP");
  });

  it("still grades the redirect when the https endpoint is down", async () => {
    const result = await probeHttpsRedirect(`${httpsBase}/broken-upgrade`, local({ httpPort }));
    expect(result.errorCode).toBe("NETWORK");
    expect(result.redirects).toHaveLength(1);
    expect(result.finding.status).toBe(Status.Warn);
    expect(result.finding.detail).toMatch(/HTTPS request then failed/);
  });

  it("is informational when nothing listens on the http port", async () => {
    const result = await probeHttpsRedirect(`${httpsBase}/`, local({ httpPort: closedPort }));
    expect(result.finding.status).toBe(Status.Info);
    expect(result.errorCode).toBe("NETWORK");
  });

  it("uses the http target's own port by default", async () => {
    const result = await probeHttpsRedirect(`${httpBase}/upgrade`, local());
    expect(result.finding.status).toBe(Status.Pass);
  });

  it("re-throws SSRF blocks instead of grading them", async () => {
    await expectScanError(
      probeHttpsRedirect(`${httpsBase}/upgrade`, { resolver, httpPort }),
      "BLOCKED_ADDRESS",
    );
    await expectScanError(
      probeHttpsRedirect(`${httpsBase}/to-private`, local({ httpPort })),
      "BLOCKED_ADDRESS",
    );
  });

  it("re-throws invalid options and aborts", async () => {
    await expectScanError(
      probeHttpsRedirect(`${httpsBase}/`, local({ httpPort: 0 })),
      "INVALID_OPTIONS",
    );
    await expectScanError(
      probeHttpsRedirect(`${httpsBase}/upgrade`, local({ httpPort, signal: AbortSignal.abort() })),
      "ABORTED",
    );
  });
});
