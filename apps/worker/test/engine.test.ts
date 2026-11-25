/**
 * The real engine end to end against mock sites on 127.0.0.1: an http site
 * and an https site with a certificate from a throwaway CA. DNS comes from a
 * fixture resolver, so no test touches the network beyond loopback.
 */
import { createServer } from "node:net";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  engineFindingRows,
  FAILURE_MESSAGES,
  runEngine,
  storedReport,
  TargetError,
} from "../src/engine.js";
import { caa, fixtureResolver, TestPki } from "./helpers/core.js";
import { type MockSite, startHttpSite, startHttpsSite } from "./helpers/servers.js";

let http: MockSite;
let https: MockSite;
let ca: string;

const resolver = (hostname: string) =>
  Promise.resolve(hostname === "shop.test" ? [{ address: "127.0.0.1", family: 4 as const }] : []);

const dnsResolver = fixtureResolver({
  "shop.test": { txt: ["v=spf1 -all"], caa: [caa("issue", "letsencrypt.org")] },
  "_dmarc.shop.test": { txt: ["v=DMARC1; p=reject"] },
});

beforeAll(async () => {
  const pki = new TestPki();
  const root = pki.createCa();
  ca = root.cert;
  const leaf = pki.issue({ commonName: "shop.test", sans: ["DNS:shop.test"], issuer: root });
  http = await startHttpSite();
  https = await startHttpsSite(leaf);
});

afterAll(async () => {
  await http.close();
  await https.close();
});

describe("runEngine", () => {
  it("runs every section against an https site", async () => {
    const result = await runEngine(`https://shop.test:${String(https.port)}`, {
      timeoutMs: 5_000,
      allowPrivate: true,
      firstPartyHosts: [],
      resolver,
      dnsResolver,
      ca,
    });
    expect(result.finalUrl).toBe(`https://shop.test:${String(https.port)}/`);
    expect(result.httpStatus).toBe(200);
    expect(result.grade).toBe(result.headers.grade);
    expect(result.tls.status).toBe("ok");
    expect(result.dns.status).toBe("ok");
    expect(result.wellKnown.status).toBe("ok");
    expect(https.requests).toEqual(
      expect.arrayContaining(["/", "/.well-known/security.txt", "/robots.txt"]),
    );

    const rows = engineFindingRows(result);
    const categories = [...new Set(rows.map((r) => r.category))];
    expect(categories).toEqual(["HEADERS", "CONTENT", "TLS", "DNS", "WELL_KNOWN"]);
    expect(rows.find((r) => r.check === "Subresource Integrity")?.status).toBe("FAIL");

    // The stored report is plain JSON (dates as strings) and round-trips.
    const stored = storedReport(result) as {
      tls: { report: { snapshot: { certificate: { validTo: unknown } } } };
    };
    expect(typeof stored.tls.report.snapshot.certificate.validTo).toBe("string");
  });

  it("treats the owner's firstPartyHosts as first-party for SRI", async () => {
    const result = await runEngine(`https://shop.test:${String(https.port)}`, {
      timeoutMs: 5_000,
      allowPrivate: true,
      firstPartyHosts: ["assets.cdn-provider.test"],
      resolver,
      dnsResolver,
      ca,
    });
    expect(result.content.subresourceIntegrity).toEqual([]);
  });

  it("skips TLS on http and DNS on an IP address, and still succeeds", async () => {
    const result = await runEngine(`http://127.0.0.1:${String(http.port)}`, {
      timeoutMs: 5_000,
      allowPrivate: true,
      firstPartyHosts: [],
    });
    expect(result.tls).toMatchObject({ status: "skipped" });
    expect(result.dns).toMatchObject({ status: "skipped" });
    expect(result.wellKnown.status).toBe("ok");
    expect(engineFindingRows(result).some((r) => r.category === "TLS")).toBe(false);
  });

  it("records a failed optional section without failing the scan", async () => {
    const broken = await runEngine(`https://shop.test:${String(https.port)}`, {
      timeoutMs: 5_000,
      allowPrivate: true,
      firstPartyHosts: [],
      resolver,
      dnsResolver: {
        txt: () => Promise.reject(new Error("resolver exploded")),
        caa: () => Promise.reject(new Error("resolver exploded")),
      },
      ca,
    });
    expect(broken.dns).toEqual({
      status: "error",
      code: "INTERNAL",
      message: "This check failed unexpectedly.",
    });
    expect(broken.tls.status).toBe("ok");
  });

  it("blocks loopback targets unless private targets are allowed (the SSRF guard)", async () => {
    const before = https.requests.length;
    const error = await runEngine(`https://shop.test:${String(https.port)}`, {
      timeoutMs: 5_000,
      allowPrivate: false,
      firstPartyHosts: [],
      resolver,
      dnsResolver,
      ca,
    }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(TargetError);
    expect(error).toMatchObject({
      code: "BLOCKED_ADDRESS",
      userMessage: FAILURE_MESSAGES.BLOCKED_ADDRESS,
    });
    // Refused at connect time: the mock site never saw a request.
    expect(https.requests).toHaveLength(before);
  });

  it("turns an unreachable site into a TargetError with a fixed message", async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
    const { port } = closed.address() as { port: number };
    await new Promise<void>((resolve) =>
      closed.close(() => {
        resolve();
      }),
    );
    const error = await runEngine(`http://127.0.0.1:${String(port)}`, {
      timeoutMs: 5_000,
      allowPrivate: true,
      firstPartyHosts: [],
    }).catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "NETWORK", userMessage: FAILURE_MESSAGES.NETWORK });
  });

  it("has a user-safe message for every core error code", () => {
    for (const message of Object.values(FAILURE_MESSAGES)) {
      expect(message).toMatch(/^[A-Z][^<>]{5,200}\.$/);
    }
  });
});
