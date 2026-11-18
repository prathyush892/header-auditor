/**
 * Integration tests for fetchText() and analyzeWellKnown() over real sockets.
 * Servers listen on 127.0.0.1 only; the *.test hostnames are mapped there by
 * an injected resolver and route on the Host header. The https server uses a
 * certificate minted at test time. Nothing outside 127.0.0.1 is contacted:
 * the one redirect to a link-local address is refused by the SSRF guard
 * before any connection.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  analyzeWellKnown,
  fetchText,
  fetchWellKnown,
  ScanError,
  Status,
  type Resolver,
  type ScanErrorCode,
  type WellKnownOptions,
} from "../src/index.js";
import { TestPki } from "./helpers/pki.js";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

const HOSTS = [
  "good.test",
  "legacy.test",
  "spa.test",
  "redir.test",
  "slow.test",
  "big.test",
  "echo.test",
];
const NOW = new Date("2026-11-18T12:00:00Z");
const pki = new TestPki();
/** `${host}${path}` → handler. */
const routes = new Map<string, Handler>();
const servers: Server[] = [];
const requested: string[] = [];
let caCert: string;
let httpsPort: number;
let httpPort: number;

const resolver: Resolver = (hostname) => {
  if (HOSTS.includes(hostname)) return Promise.resolve([{ address: "127.0.0.1", family: 4 }]);
  if (hostname === "private.test") return Promise.resolve([{ address: "10.0.0.5", family: 4 }]);
  return Promise.reject(new Error(`ENOTFOUND ${hostname}`));
};

function local(extra: WellKnownOptions = {}): WellKnownOptions {
  return { allowAddresses: ["127.0.0.1"], resolver, ca: caCert, now: NOW, ...extra };
}

function base(host: string, scheme: "https" | "http" = "https"): string {
  return `${scheme}://${host}:${String(scheme === "https" ? httpsPort : httpPort)}`;
}

const router: Handler = (req, res) => {
  const host = (req.headers.host ?? "").split(":")[0] ?? "";
  const path = new URL(req.url ?? "/", "http://placeholder").pathname;
  requested.push(`${host}${path}`);
  const handler = routes.get(`${host}${path}`) ?? routes.get(`${host}*`);
  if (handler) handler(req, res);
  else res.writeHead(404, { "content-type": "text/plain" }).end("not found");
};

function text(body: string, contentType = "text/plain; charset=utf-8"): Handler {
  return (_req, res) => {
    res.writeHead(200, { "content-type": contentType }).end(body);
  };
}

function redirect(location: () => string): Handler {
  return (_req, res) => {
    res.writeHead(301, { location: location() }).end();
  };
}

async function listen(server: Server): Promise<number> {
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

async function expectScanError(promise: Promise<unknown>, code: ScanErrorCode): Promise<void> {
  const err: unknown = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(ScanError);
  expect((err as ScanError).code).toBe(code);
}

function securityTxt(canonical: string): string {
  return [
    "Contact: mailto:security@good.test",
    "Expires: 2027-06-30T23:59:59Z",
    `Canonical: ${canonical}`,
  ].join("\n");
}

beforeAll(async () => {
  const ca = pki.createCa();
  caCert = ca.cert;
  const leaf = pki.issue({
    commonName: "good.test",
    sans: HOSTS.map((h) => `DNS:${h}`),
    issuer: ca,
  });
  httpsPort = await listen(createHttpsServer(leaf, router));
  httpPort = await listen(createServer(router));

  routes.set(
    "good.test/.well-known/security.txt",
    // The canonical URL depends on the scheme it's fetched over.
    (req, res) => {
      const scheme = (req.socket as { encrypted?: boolean }).encrypted ? "https" : "http";
      text(securityTxt(`${base("good.test", scheme)}/.well-known/security.txt`))(req, res);
    },
  );
  routes.set(
    "good.test/robots.txt",
    text("User-agent: *\nDisallow: /search\nDisallow: /wp-admin/\n"),
  );

  routes.set("legacy.test/security.txt", (req, res) => {
    text(securityTxt(`${base("legacy.test")}/security.txt`))(req, res);
  });
  routes.set(
    "legacy.test/robots.txt",
    text("User-agent: *\nDisallow: /admin/\nDisallow: /.git/\nDisallow: /db.sql\n"),
  );

  // A single-page app: every path is the same HTML shell with status 200.
  routes.set("spa.test*", text("<!doctype html><div id=root></div>", "text/html"));

  routes.set(
    "redir.test/.well-known/security.txt",
    redirect(() => `${base("good.test")}/.well-known/security.txt`),
  );
  routes.set(
    "redir.test/robots.txt",
    redirect(() => "https://169.254.169.254/robots.txt"),
  );

  routes.set("slow.test/robots.txt", () => {
    // Never answers: the request must time out.
  });

  routes.set(
    "big.test/.well-known/security.txt",
    text(`Contact: mailto:a@big.test\n${"#".repeat(40 * 1024)}`),
  );
  routes.set("big.test/robots.txt", text(""));

  routes.set("echo.test/headers", (req, res) => {
    text(JSON.stringify({ accept: req.headers.accept }), "application/json")(req, res);
  });
  routes.set("echo.test/gone", (_req, res) => {
    res.writeHead(410, { "content-type": "text/plain" }).end("gone for good");
  });
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

describe("fetchText", () => {
  it("reads a 2xx body and sends the Accept header", async () => {
    const res = await fetchText(`${base("echo.test")}/headers`, local({}));
    expect(res.statusCode).toBe(200);
    expect(res.contentType).toBe("application/json");
    expect(JSON.parse(res.text ?? "{}")).toEqual({ accept: "text/plain, */*;q=0.5" });
  });

  it("uses a custom Accept header", async () => {
    const res = await fetchText(`${base("echo.test")}/headers`, {
      ...local(),
      accept: "text/x-custom",
    });
    expect(JSON.parse(res.text ?? "{}")).toEqual({ accept: "text/x-custom" });
  });

  it("returns non-2xx statuses without reading the body", async () => {
    const res = await fetchText(`${base("echo.test")}/gone`, local());
    expect(res.statusCode).toBe(410);
    expect(res.text).toBeUndefined();
    expect(res.bytes).toBe(0);
  });

  it("truncates at maxBytes", async () => {
    const res = await fetchText(`${base("big.test")}/.well-known/security.txt`, {
      ...local(),
      maxBytes: 100,
    });
    expect(res.bytes).toBe(100);
    expect(res.truncated).toBe(true);
  });

  it.each([
    [{ accept: "" }],
    [{ accept: "text/plain\r\nX-Injected: 1" }],
    [{ maxBytes: -1 }],
    [{ maxBytes: 1.5 }],
  ])("rejects invalid options %j", async (bad) => {
    await expectScanError(
      fetchText(`${base("echo.test")}/headers`, { ...local(), ...bad }),
      "INVALID_OPTIONS",
    );
  });

  it("applies the SSRF policy", async () => {
    await expectScanError(
      fetchText(`${base("echo.test")}/headers`, { resolver, ca: caCert }),
      "BLOCKED_ADDRESS",
    );
  });
});

describe("analyzeWellKnown", () => {
  it("passes a site with a valid security.txt and a clean robots.txt", async () => {
    const report = await analyzeWellKnown(`${base("good.test")}/some/page?q=1`, local());
    expect(report.origin).toBe(base("good.test"));
    expect(report.findings.map((f) => [f.check, f.status])).toEqual([
      ["security.txt", Status.Pass],
      ["robots.txt", Status.Pass],
    ]);
    expect(report.grade).toBe("A");
    expect(report.securityTxt.parsed?.fields.map((f) => f.name)).toEqual([
      "contact",
      "expires",
      "canonical",
    ]);
    expect(report.robotsTxt.sensitivePaths.map((p) => p.category)).toEqual(["framework-default"]);
  });

  it("falls back to the legacy path and flags sensitive robots entries without fetching them", async () => {
    requested.length = 0;
    const report = await analyzeWellKnown(base("legacy.test"), local());
    const [security, robots] = report.findings;
    expect(security?.status).toBe(Status.Warn);
    expect(security?.recommendation).toContain("legacy path");
    expect(robots?.status).toBe(Status.Warn);
    expect(robots?.score).toBe(3);
    expect(report.robotsTxt.sensitivePaths.map((p) => p.path)).toEqual([
      "/admin/",
      "/.git/",
      "/db.sql",
    ]);
    // Only the three well-known paths were requested, never the advertised ones.
    expect([...requested].sort()).toEqual([
      "legacy.test/.well-known/security.txt",
      "legacy.test/robots.txt",
      "legacy.test/security.txt",
    ]);
  });

  it("treats an SPA's HTML catch-all as missing", async () => {
    const report = await analyzeWellKnown(base("spa.test"), local());
    const [security, robots] = report.findings;
    expect(report.securityTxt.observation.kind).toBe("missing");
    expect(security?.detail).toContain("served as HTML");
    expect(security?.score).toBe(0);
    expect(robots?.status).toBe(Status.Pass);
  });

  it("follows redirects, warns on a cross-host security.txt and records a blocked robots redirect as an error", async () => {
    const report = await analyzeWellKnown(base("redir.test"), local());
    const [security, robots] = report.findings;
    expect(security?.status).toBe(Status.Warn);
    expect(security?.recommendation).toContain("another host");
    expect(robots?.status).toBe(Status.Info);
    expect(robots?.detail).toContain("BLOCKED_ADDRESS");
    expect(report.robotsTxt.observation).toMatchObject({ kind: "error", code: "BLOCKED_ADDRESS" });
  });

  it("turns a timeout into an unscored finding", async () => {
    const report = await analyzeWellKnown(base("slow.test"), local({ timeoutMs: 300 }));
    const [security, robots] = report.findings;
    expect(security?.score).toBe(0);
    expect(robots?.status).toBe(Status.Info);
    expect(robots?.detail).toContain("TIMEOUT");
    // Only security.txt is scored.
    expect(report.maxScore).toBe(10);
  });

  it("fails security.txt served over plain http", async () => {
    const report = await analyzeWellKnown(base("good.test", "http"), local());
    expect(report.findings[0]?.status).toBe(Status.Fail);
    expect(report.findings[0]?.detail).toContain("plain HTTP");
  });

  it("fails an oversized security.txt and treats an empty robots.txt as missing", async () => {
    const report = await analyzeWellKnown(base("big.test"), local());
    expect(report.findings[0]?.status).toBe(Status.Fail);
    expect(report.findings[0]?.detail).toContain("Larger than");
    expect(report.robotsTxt.observation).toMatchObject({ kind: "missing", reason: "empty file" });
  });

  it.each([
    ["ftp://good.test/", "BLOCKED_SCHEME"],
    ["not a url", "INVALID_URL"],
    ["https://10.0.0.1/", "BLOCKED_ADDRESS"],
  ] as const)("rejects target %s", async (target, code) => {
    await expectScanError(analyzeWellKnown(target, local()), code);
  });

  it("rethrows when the target's hostname resolves to a blocked address", async () => {
    await expectScanError(analyzeWellKnown("https://private.test/", local()), "BLOCKED_ADDRESS");
  });

  it.each([[{ timeoutMs: 0 }], [{ allowAddresses: ["not-an-ip"] }], [{ now: new Date("nope") }]])(
    "rejects invalid options %j",
    async (bad) => {
      await expectScanError(
        analyzeWellKnown(base("good.test"), { ...local(), ...bad }),
        "INVALID_OPTIONS",
      );
    },
  );

  it("rethrows cancellation", async () => {
    const controller = new AbortController();
    controller.abort();
    await expectScanError(
      analyzeWellKnown(base("good.test"), local({ signal: controller.signal })),
      "ABORTED",
    );
  });
});

describe("fetchWellKnown", () => {
  it("reports HTTP status for a missing file", async () => {
    const obs = await fetchWellKnown(base("echo.test"), "/robots.txt", 1024, local());
    expect(obs).toMatchObject({ kind: "missing", statusCode: 404, reason: "HTTP 404" });
  });
});
