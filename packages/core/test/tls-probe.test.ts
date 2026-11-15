/**
 * Integration tests for probeTls() and scanUrl()'s https path. Every server
 * here listens on 127.0.0.1 with certificates minted at test time by a
 * throwaway PKI (test/helpers/pki.ts). "Remote" names come from an injected
 * resolver; no test touches real DNS or any other host.
 */
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import {
  createServer as createNetServer,
  type AddressInfo,
  type Server as NetServer,
  type Socket,
} from "node:net";
import { createServer as createTlsServer, type TlsOptions } from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  probeTls,
  scanUrl,
  ScanError,
  type Resolver,
  type ScanErrorCode,
  type TlsProbeOptions,
} from "../src/index.js";
import { TestPki, type KeyPair } from "./helpers/pki.js";

interface Running {
  port: number;
  /** TCP connections accepted. */
  connections: number;
  /** Bytes of application data received after a handshake. */
  appBytes: number;
  /** SNI names the server was asked for. */
  serverNames: string[];
  close: () => Promise<void>;
}

const servers: Running[] = [];
const pki = new TestPki();
let ca: KeyPair;
let otherCa: KeyPair;
let goodLeaf: KeyPair;

const LOCAL: TlsProbeOptions = { allowAddresses: ["127.0.0.1"] };

function fixtureResolver(table: Record<string, string>): Resolver {
  return (hostname) => {
    const address = new Map(Object.entries(table)).get(hostname);
    if (address === undefined) return Promise.reject(new Error(`ENOTFOUND ${hostname}`));
    return Promise.resolve([{ address, family: 4 }]);
  };
}

async function listen(server: NetServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

/** Starts `server` on 127.0.0.1 and counts its TCP connections. */
async function track(server: NetServer, running: Running = newRunning()): Promise<Running> {
  const sockets = new Set<Socket>();
  server.on("connection", (s: Socket) => {
    running.connections++;
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
  });
  running.port = await listen(server);
  running.close = () =>
    new Promise<void>((resolve) => {
      for (const s of sockets) s.destroy();
      server.close(() => {
        resolve();
      });
    });
  servers.push(running);
  return running;
}

function newRunning(): Running {
  return { port: 0, connections: 0, appBytes: 0, serverNames: [], close: () => Promise.resolve() };
}

function tlsServer(options: TlsOptions): Promise<Running> {
  const running = newRunning();
  const server = createTlsServer(options, (socket) => {
    if (typeof socket.servername === "string") running.serverNames.push(socket.servername);
    socket.on("data", (chunk: Buffer) => (running.appBytes += chunk.length));
    socket.on("error", () => undefined);
  });
  server.on("tlsClientError", () => undefined);
  return track(server, running);
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

const url = (port: number, host = "127.0.0.1"): string => `https://${host}:${String(port)}/`;

beforeAll(() => {
  ca = pki.createCa();
  otherCa = pki.createCa("Some Other CA");
  goodLeaf = pki.issue({
    commonName: "app.test",
    sans: ["DNS:app.test", "IP:127.0.0.1"],
    issuer: ca,
  });
});

afterAll(async () => {
  await Promise.all(servers.map((s) => s.close()));
  pki.cleanup();
});

describe("probeTls against a well-configured server", () => {
  let server: Running;
  beforeAll(async () => {
    server = await tlsServer({ ...goodLeaf, minVersion: "TLSv1.2" });
  });

  it("grades a CA-issued, modern config A", async () => {
    const report = await probeTls(url(server.port), { ...LOCAL, ca: ca.cert });
    expect(report.snapshot.protocol).toBe("TLSv1.3");
    expect(report.snapshot.authorized).toBe(true);
    expect(report.snapshot.legacy).toEqual({ TLSv1: "rejected", "TLSv1.1": "rejected" });
    expect(report.snapshot.certificate?.keyType).toBe("EC");
    expect(report.snapshot.certificate?.keyBits).toBe(256);
    expect(report.snapshot.certificate?.issuerOrganization).toBe("Header Auditor Tests");
    expect(report.findings.every((f) => f.status === "pass")).toBe(true);
    expect(report.grade).toBe("A");
  });

  it("only handshakes: never writes application data", async () => {
    const before = server.appBytes;
    await probeTls(url(server.port), { ...LOCAL, ca: ca.cert });
    expect(server.appBytes).toBe(before);
  });

  it("sends SNI for hostnames (via the injected resolver) and checks the cert against that name", async () => {
    const report = await probeTls(url(server.port, "app.test"), {
      ...LOCAL,
      ca: ca.cert,
      resolver: fixtureResolver({ "app.test": "127.0.0.1" }),
    });
    expect(server.serverNames).toContain("app.test");
    expect(report.host).toBe("app.test");
    expect(report.findings.find((f) => f.check === "Certificate hostname")?.status).toBe("pass");
  });

  it("fails the hostname check when the name isn't on the certificate", async () => {
    const report = await probeTls(url(server.port, "other.test"), {
      ...LOCAL,
      ca: ca.cert,
      resolver: fixtureResolver({ "other.test": "127.0.0.1" }),
    });
    expect(report.findings.find((f) => f.check === "Certificate hostname")?.status).toBe("fail");
    expect(report.grade).toBe("F");
    expect(report.gradeCappedBy).toContain("Certificate hostname");
  });

  it("does not trust the issuer without the right CA (system roots / other CA)", async () => {
    const withoutCa = await probeTls(url(server.port), LOCAL);
    expect(withoutCa.snapshot.authorized).toBe(false);
    const wrongCa = await probeTls(url(server.port), { ...LOCAL, ca: otherCa.cert });
    expect(wrongCa.snapshot.authorized).toBe(false);
    expect(wrongCa.findings.find((f) => f.check === "Certificate trust")?.status).toBe("fail");
  });

  it("reports legacy versions as untested when probing is turned off", async () => {
    const report = await probeTls(url(server.port), { ...LOCAL, ca: ca.cert, probeLegacy: false });
    expect(report.snapshot.legacy).toEqual({ TLSv1: "untested", "TLSv1.1": "untested" });
    expect(report.findings.find((f) => f.check === "Legacy TLS versions")?.status).toBe("info");
  });

  it("flags expiry using the injected clock", async () => {
    const future = new Date(Date.now() + 365 * 86_400_000);
    const report = await probeTls(url(server.port), { ...LOCAL, ca: ca.cert, now: future });
    expect(report.findings.find((f) => f.check === "Certificate validity")?.detail).toMatch(
      /expired/,
    );
    expect(report.grade).toBe("F");
  });
});

describe("probeTls against weak servers", () => {
  it("detects a self-signed certificate", async () => {
    const self = pki.issue({ commonName: "localhost", sans: ["IP:127.0.0.1"] });
    const server = await tlsServer(self);
    const report = await probeTls(url(server.port), LOCAL);
    expect(report.snapshot.authorizationError).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");
    expect(report.snapshot.certificate?.selfIssued).toBe(true);
    expect(report.findings.find((f) => f.check === "Certificate trust")?.detail).toMatch(
      /self-signed/,
    );
    expect(report.grade).toBe("F");
  });

  it("detects TLS 1.0/1.1 still being accepted", async () => {
    const server = await tlsServer({
      ...goodLeaf,
      minVersion: "TLSv1",
      ciphers: "DEFAULT@SECLEVEL=0",
    });
    const report = await probeTls(url(server.port), { ...LOCAL, ca: ca.cert });
    expect(report.snapshot.legacy).toEqual({ TLSv1: "accepted", "TLSv1.1": "accepted" });
    expect(report.findings.find((f) => f.check === "Legacy TLS versions")?.status).toBe("fail");
  });

  it("fails the protocol check when the server tops out at TLS 1.1", async () => {
    const server = await tlsServer({
      ...goodLeaf,
      minVersion: "TLSv1",
      maxVersion: "TLSv1.1",
      ciphers: "DEFAULT@SECLEVEL=0",
    });
    const report = await probeTls(url(server.port), { ...LOCAL, ca: ca.cert });
    expect(report.snapshot.protocol).toBe("TLSv1.1");
    expect(report.snapshot.legacy["TLSv1.1"]).toBe("accepted");
    expect(report.findings.find((f) => f.check === "TLS protocol")?.status).toBe("fail");
    expect(report.grade).toBe("F");
  });

  it("flags static-RSA key exchange and a 1024-bit RSA key", async () => {
    const weak = pki.issue({
      commonName: "app.test",
      sans: ["IP:127.0.0.1"],
      key: "rsa1024",
      issuer: ca,
    });
    const server = await tlsServer({
      ...weak,
      maxVersion: "TLSv1.2",
      ciphers: "AES128-SHA@SECLEVEL=0",
    });
    const report = await probeTls(url(server.port), { ...LOCAL, ca: ca.cert });
    expect(report.snapshot.cipher.standardName).toBe("TLS_RSA_WITH_AES_128_CBC_SHA");
    const cipher = report.findings.find((f) => f.check === "Cipher suite");
    expect(cipher?.detail).toMatch(/no forward secrecy/);
    const key = report.findings.find((f) => f.check === "Certificate key");
    expect([key?.status, key?.detail]).toEqual(["fail", expect.stringContaining("RSA 1024-bit")]);
  });

  it("flags a certificate that expires within the critical window", async () => {
    const soon = pki.issue({ commonName: "app.test", sans: ["IP:127.0.0.1"], days: 3, issuer: ca });
    const server = await tlsServer(soon);
    const report = await probeTls(url(server.port), { ...LOCAL, ca: ca.cert });
    const validity = report.findings.find((f) => f.check === "Certificate validity");
    expect([validity?.status, validity?.score]).toEqual(["fail", 5]);
  });
});

describe("probeTls safety and errors", () => {
  let server: Running;
  beforeAll(async () => {
    server = await tlsServer(goodLeaf);
  });

  it("blocks loopback IP literals unless allowed, before connecting", async () => {
    const before = server.connections;
    await expectScanError(probeTls(url(server.port)), "BLOCKED_ADDRESS");
    expect(server.connections).toBe(before);
  });

  it("blocks hostnames that resolve to private addresses, before connecting", async () => {
    const before = server.connections;
    const err = await expectScanError(
      probeTls(url(server.port, "internal.test"), {
        resolver: fixtureResolver({ "internal.test": "127.0.0.1" }),
      }),
      "BLOCKED_ADDRESS",
    );
    expect(err.message).toContain("internal.test");
    expect(server.connections).toBe(before);
  });

  it("maps DNS failures", async () => {
    await expectScanError(
      probeTls("https://missing.test/", { resolver: fixtureResolver({}) }),
      "DNS_FAILURE",
    );
  });

  it.each([
    ["http://127.0.0.1/", "INVALID_URL"],
    ["ftp://127.0.0.1/", "BLOCKED_SCHEME"],
    ["not a url", "INVALID_URL"],
    ["https://user:pw@127.0.0.1/", "INVALID_URL"],
  ] as const)("rejects %s with %s", async (target, code) => {
    await expectScanError(probeTls(target, LOCAL), code);
  });

  it.each([
    [{ timeoutMs: 0 }],
    [{ timeoutMs: 999_999 }],
    [{ expiryWarnDays: -1 }],
    [{ ca: "not pem" }],
    [{ ca: [] as string[] }],
    [{ allowAddresses: ["nope"] }],
  ])("rejects bad options %j before connecting", async (opts) => {
    const before = server.connections;
    await expectScanError(probeTls(url(server.port), { ...LOCAL, ...opts }), "INVALID_OPTIONS");
    expect(server.connections).toBe(before);
  });

  it("times out on a server that never completes the handshake", async () => {
    const silent = createNetServer((s) => s.on("error", () => undefined));
    const r = await track(silent);
    const started = Date.now();
    await expectScanError(probeTls(url(r.port), { ...LOCAL, timeoutMs: 300 }), "TIMEOUT");
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("honours an already-aborted signal", async () => {
    const controller = new AbortController();
    controller.abort();
    await expectScanError(
      probeTls(url(server.port), { ...LOCAL, signal: controller.signal }),
      "ABORTED",
    );
  });

  it("reports TLS_ERROR when the port speaks plain HTTP", async () => {
    const plain = createHttpServer((_req, res) => res.end("hi"));
    const r = await track(plain);
    await expectScanError(probeTls(url(r.port), LOCAL), "TLS_ERROR");
  });

  it("reports NETWORK when nothing is listening", async () => {
    const closed = createNetServer();
    const port = await listen(closed);
    await new Promise<void>((resolve) => {
      closed.close(() => {
        resolve();
      });
    });
    await expectScanError(probeTls(url(port), LOCAL), "NETWORK");
  });
});

describe("scanUrl over https", () => {
  let port: number;
  beforeAll(async () => {
    const server = createHttpsServer(goodLeaf, (_req, res) => {
      res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
      res.writeHead(200, { "content-type": "text/html" }).end("<p>ok</p>");
    });
    const r = await track(server);
    port = r.port;
  });

  it("verifies the certificate against `ca` and grades HSTS as https", async () => {
    const { report } = await scanUrl(url(port), { allowAddresses: ["127.0.0.1"], ca: ca.cert });
    expect(report.url).toBe(url(port));
    expect(report.findings.find((f) => f.check === "Strict-Transport-Security")?.status).toBe(
      "pass",
    );
  });

  it("refuses untrusted certificates with TLS_ERROR (never silently ignored)", async () => {
    await expectScanError(scanUrl(url(port), { allowAddresses: ["127.0.0.1"] }), "TLS_ERROR");
    await expectScanError(
      scanUrl(url(port), { allowAddresses: ["127.0.0.1"], ca: otherCa.cert }),
      "TLS_ERROR",
    );
  });

  it("refuses a hostname mismatch with TLS_ERROR", async () => {
    await expectScanError(
      scanUrl(url(port, "other.test"), {
        allowAddresses: ["127.0.0.1"],
        ca: ca.cert,
        resolver: fixtureResolver({ "other.test": "127.0.0.1" }),
      }),
      "TLS_ERROR",
    );
  });

  it("validates the ca option", async () => {
    await expectScanError(scanUrl(url(port), { ca: "garbage" }), "INVALID_OPTIONS");
  });
});
