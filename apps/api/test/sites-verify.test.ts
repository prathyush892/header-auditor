/**
 * POST /sites/:id/verify over HTTP, on the memory stores and on Postgres
 * (PGlite) through the Prisma stores. DNS answers come from an in-memory
 * zone the tests edit, so every outcome is reachable without a network.
 *
 * The property that matters most: publishing *your* token verifies *your*
 * site only. Another account that added the same URL has a different token
 * and stays unverified, and nobody can verify a site they don't own.
 */
import { createPrismaClient, type PrismaClient } from "@header-auditor/db";
import { DnsLookupError, type DnsErrorCode, type DnsResolver } from "@header-auditor/core";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { createPrismaAuthStore } from "../src/auth/prisma-store.js";
import { MemoryAuthStore } from "../src/auth/store.js";
import type { Env } from "../src/config.js";
import { createPrismaSiteStore } from "../src/sites/prisma-store.js";
import { MemorySiteStore, type SiteStore } from "../src/sites/store.js";
import { createDomainVerifier } from "../src/verification/domain.js";
import {
  fastHasher,
  ORIGIN,
  register,
  type Session,
  sessionFrom,
  TestClock,
} from "./helpers/auth.js";
import { createTestApp, type LogCapture } from "./helpers/app.js";
import { startTestDatabase, type TestDatabase } from "./helpers/database.js";

let testDb: TestDatabase;
let prisma: PrismaClient;

beforeAll(async () => {
  testDb = await startTestDatabase();
  expect(new URL(testDb.url).hostname).toBe("127.0.0.1");
  prisma = createPrismaClient({ databaseUrl: testDb.url, maxConnections: 4 });
});

afterAll(async () => {
  await prisma.$disconnect();
  await testDb.stop();
});

/** A zone the test can edit between requests, plus a log of every query. */
class EditableZone implements DnsResolver {
  readonly records = new Map<string, string[]>();
  readonly failures = new Map<string, DnsErrorCode>();
  readonly queries: string[] = [];

  txt(name: string): Promise<readonly string[]> {
    this.queries.push(name);
    const failure = this.failures.get(name);
    if (failure !== undefined) return Promise.reject(new DnsLookupError(name, "TXT", failure));
    return Promise.resolve(this.records.get(name) ?? []);
  }

  caa(): Promise<never[]> {
    return Promise.resolve([]);
  }

  publish(record: { name: string; value: string }): void {
    this.records.set(record.name, [...(this.records.get(record.name) ?? []), record.value]);
  }
}

interface Harness {
  readonly app: FastifyInstance;
  readonly logs: LogCapture;
  readonly zone: EditableZone;
  readonly clock: TestClock;
}

const BASE_ENV: Env = { AUTH_COOKIE_SECURE: "false", SITES_VERIFY_ATTEMPTS_PER_WINDOW: "50" };

type Backend = readonly [
  string,
  () => { auth: MemoryAuthStore | ReturnType<typeof createPrismaAuthStore>; sites: SiteStore },
];

const BACKENDS: readonly Backend[] = [
  ["memory stores", () => ({ auth: new MemoryAuthStore(), sites: new MemorySiteStore() })],
  [
    "Prisma stores (PGlite)",
    () => ({ auth: createPrismaAuthStore(prisma), sites: createPrismaSiteStore(prisma) }),
  ],
];

async function harness(stores: ReturnType<Backend[1]>, env: Env = {}): Promise<Harness> {
  const zone = new EditableZone();
  const clock = new TestClock(Date.parse("2026-11-26T15:00:00.000Z"));
  const { app, logs } = await createTestApp({
    env: { ...BASE_ENV, ...env },
    auth: { store: stores.auth, hasher: fastHasher(), pruneIntervalMs: 0 },
    sites: {
      store: stores.sites,
      verification: { verifier: createDomainVerifier(zone), now: clock.now },
    },
  });
  return { app, logs, zone, clock };
}

let userCounter = 0;

async function signUp(app: FastifyInstance): Promise<Session> {
  userCounter += 1;
  const response = await register(app, `verify${String(userCounter)}@example.test`);
  expect(response.statusCode).toBe(201);
  return sessionFrom(response);
}

function call(
  app: FastifyInstance,
  session: Session | null,
  method: "GET" | "POST" | "PATCH",
  url: string,
  payload?: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<LightMyRequestResponse> {
  return app.inject({
    method,
    url,
    headers: {
      origin: ORIGIN,
      ...(session === null ? {} : { cookie: session.cookie, "x-csrf-token": session.csrfToken }),
      ...headers,
    },
    ...(payload === undefined ? {} : { payload }),
  });
}

interface PublicSiteJson {
  id: string;
  url: string;
  verified: boolean;
  verifiedAt: string | null;
  verificationToken: string;
  verificationRecord: { name: string; type: "TXT"; value: string } | null;
}

let siteCounter = 0;

async function addSite(
  app: FastifyInstance,
  session: Session,
  url?: string,
): Promise<PublicSiteJson> {
  siteCounter += 1;
  const response = await call(app, session, "POST", "/sites", {
    name: `Site ${String(siteCounter)}`,
    url: url ?? `https://site${String(siteCounter)}.example.com`,
  });
  expect(response.statusCode, response.body).toBe(201);
  return response.json();
}

function verify(app: FastifyInstance, session: Session | null, id: string) {
  return call(app, session, "POST", `/sites/${id}/verify`);
}

function errorOf(response: LightMyRequestResponse): { code: string; message: string } {
  return response.json<{ error: { code: string; message: string } }>().error;
}

describe.each(BACKENDS)("POST /sites/:id/verify (%s)", (_name, makeStores) => {
  let h: Harness;
  let me: Session;

  beforeAll(async () => {
    h = await harness(makeStores());
    me = await signUp(h.app);
  });

  afterAll(async () => {
    await h.app.close();
  });

  it("shows the record to publish on every site", async () => {
    const site = await addSite(h.app, me, "https://www.shop.example.com/");
    expect(site.verified).toBe(false);
    expect(site.verificationRecord).toEqual({
      name: "_header-auditor-challenge.www.shop.example.com",
      type: "TXT",
      value: `header-auditor-verification=${site.verificationToken}`,
    });
  });

  it("verifies once the TXT record is published, which unlocks scheduling", async () => {
    const site = await addSite(h.app, me);
    const record = site.verificationRecord;
    if (record === null) throw new Error("expected a verification record");

    const missing = await verify(h.app, me, site.id);
    expect(missing.statusCode).toBe(422);
    expect(errorOf(missing).code).toBe("VERIFICATION_RECORD_MISSING");
    expect(errorOf(missing).message).toContain(record.name);
    expect(errorOf(missing).message).toContain(record.value);

    const blocked = await call(h.app, me, "PATCH", `/sites/${site.id}`, { schedule: "daily" });
    expect(errorOf(blocked).code).toBe("SITE_NOT_VERIFIED");

    h.zone.publish(record);
    const ok = await verify(h.app, me, site.id);
    expect(ok.statusCode, ok.body).toBe(200);
    expect(ok.json()).toMatchObject({
      id: site.id,
      verified: true,
      verifiedAt: h.clock.now().toISOString(),
    });
    expect(h.zone.queries.at(-1)).toBe(record.name);

    const read = await call(h.app, me, "GET", `/sites/${site.id}`);
    expect(read.json<PublicSiteJson>().verified).toBe(true);

    const scheduled = await call(h.app, me, "PATCH", `/sites/${site.id}`, { schedule: "daily" });
    expect(scheduled.statusCode, scheduled.body).toBe(200);
    expect(scheduled.json()).toMatchObject({ schedule: "daily", verified: true });
  });

  it("is idempotent: an already verified site answers 200 without a DNS query", async () => {
    const site = await addSite(h.app, me);
    if (site.verificationRecord === null) throw new Error("expected a record");
    h.zone.publish(site.verificationRecord);
    const first = await verify(h.app, me, site.id);
    const verifiedAt = first.json<PublicSiteJson>().verifiedAt;

    h.clock.advance(60_000);
    const queries = h.zone.queries.length;
    const second = await verify(h.app, me, site.id);
    expect(second.statusCode).toBe(200);
    expect(second.json<PublicSiteJson>().verifiedAt).toBe(verifiedAt);
    expect(h.zone.queries).toHaveLength(queries);
  });

  it("reports a record with someone else's token as a mismatch", async () => {
    const site = await addSite(h.app, me);
    const name = site.verificationRecord?.name ?? "";
    h.zone.publish({ name, value: `header-auditor-verification=${"0".repeat(64)}` });
    const response = await verify(h.app, me, site.id);
    expect(response.statusCode).toBe(422);
    expect(errorOf(response).code).toBe("VERIFICATION_TOKEN_MISMATCH");
    expect(
      (await call(h.app, me, "GET", `/sites/${site.id}`)).json<PublicSiteJson>().verified,
    ).toBe(false);
  });

  it("answers 503 with a generic message when DNS fails, and stays unverified", async () => {
    const site = await addSite(h.app, me);
    h.zone.failures.set(site.verificationRecord?.name ?? "", "TIMEOUT");
    const response = await verify(h.app, me, site.id);
    expect(response.statusCode).toBe(503);
    expect(errorOf(response)).toEqual(
      expect.objectContaining({
        code: "VERIFICATION_DNS_UNAVAILABLE",
        message: "Internal Server Error",
      }),
    );
    expect(
      (await call(h.app, me, "GET", `/sites/${site.id}`)).json<PublicSiteJson>().verified,
    ).toBe(false);
  });

  it("logs the outcome and the record name, never the session", async () => {
    const site = await addSite(h.app, me);
    await verify(h.app, me, site.id);
    const line = h.logs.lines.find(
      (l) => l.msg === "site verification checked" && l.siteId === site.id,
    );
    expect(line).toMatchObject({
      outcome: "RECORD_MISSING",
      record: site.verificationRecord?.name,
    });
    expect(h.logs.text()).not.toContain(me.cookie.split("=")[1] ?? "<none>");
  });
});

describe.each(BACKENDS)("verification authorization (%s)", (_name, makeStores) => {
  let h: Harness;
  let alice: Session;
  let bob: Session;

  beforeAll(async () => {
    h = await harness(makeStores());
    alice = await signUp(h.app);
    bob = await signUp(h.app);
  });

  afterAll(async () => {
    await h.app.close();
  });

  it("requires a session and a CSRF token", async () => {
    const site = await addSite(h.app, alice);
    expect((await verify(h.app, null, site.id)).statusCode).toBe(401);
    const noCsrf = await h.app.inject({
      method: "POST",
      url: `/sites/${site.id}/verify`,
      headers: { origin: ORIGIN, cookie: alice.cookie },
    });
    expect(noCsrf.statusCode).toBe(403);
    const crossSite = await call(h.app, alice, "POST", `/sites/${site.id}/verify`, undefined, {
      origin: "https://evil.example",
    });
    expect(crossSite.statusCode).toBe(403);
  });

  it("gives another user's site, a missing site and a malformed id the same 404", async () => {
    const site = await addSite(h.app, alice);
    if (site.verificationRecord === null) throw new Error("expected a record");
    h.zone.publish(site.verificationRecord);
    for (const id of [site.id, "00000000-0000-4000-8000-000000000000", "not-a-uuid"]) {
      const response = await verify(h.app, bob, id);
      expect(response.statusCode).toBe(404);
      expect(errorOf(response).code).toBe("SITE_NOT_FOUND");
    }
    expect(
      (await call(h.app, alice, "GET", `/sites/${site.id}`)).json<PublicSiteJson>().verified,
    ).toBe(false);
  });

  it("does not let one account's record verify another account's copy of the site", async () => {
    const url = "https://shared.example.com";
    const alicesSite = await addSite(h.app, alice, url);
    const bobsSite = await addSite(h.app, bob, url);
    expect(alicesSite.verificationToken).not.toBe(bobsSite.verificationToken);
    expect(alicesSite.verificationRecord?.name).toBe(bobsSite.verificationRecord?.name);
    if (alicesSite.verificationRecord === null) throw new Error("expected a record");

    h.zone.publish(alicesSite.verificationRecord);
    expect((await verify(h.app, alice, alicesSite.id)).statusCode).toBe(200);
    const bobs = await verify(h.app, bob, bobsSite.id);
    expect(bobs.statusCode).toBe(422);
    expect(errorOf(bobs).code).toBe("VERIFICATION_TOKEN_MISMATCH");

    // Both records side by side: each account verifies its own site.
    if (bobsSite.verificationRecord === null) throw new Error("expected a record");
    h.zone.publish(bobsSite.verificationRecord);
    expect((await verify(h.app, bob, bobsSite.id)).statusCode).toBe(200);
  });
});

describe("verification rate limit", () => {
  let h: Harness;
  let me: Session;

  beforeEach(async () => {
    h = await harness(
      { auth: new MemoryAuthStore(), sites: new MemorySiteStore() },
      { SITES_VERIFY_ATTEMPTS_PER_WINDOW: "2", SITES_VERIFY_WINDOW_SECONDS: "600" },
    );
    me = await signUp(h.app);
  });

  it("counts attempts per account across sites and answers 429 with Retry-After", async () => {
    const one = await addSite(h.app, me);
    const two = await addSite(h.app, me);
    expect((await verify(h.app, me, one.id)).statusCode).toBe(422);
    expect((await verify(h.app, me, two.id)).statusCode).toBe(422);

    const queries = h.zone.queries.length;
    const limited = await verify(h.app, me, one.id);
    expect(limited.statusCode).toBe(429);
    expect(errorOf(limited).code).toBe("RATE_LIMITED");
    expect(Number(limited.headers["retry-after"])).toBeGreaterThan(0);
    expect(Number(limited.headers["retry-after"])).toBeLessThanOrEqual(600);
    // The limit is enforced before the lookup: no DNS traffic once blocked.
    expect(h.zone.queries).toHaveLength(queries);
    await h.app.close();
  });

  it("doesn't count requests for sites the caller can't see", async () => {
    const other = await signUp(h.app);
    const site = await addSite(h.app, other);
    for (let i = 0; i < 3; i++) expect((await verify(h.app, me, site.id)).statusCode).toBe(404);
    const mine = await addSite(h.app, me);
    expect((await verify(h.app, me, mine.id)).statusCode).toBe(422);
    await h.app.close();
  });
});

describe("sites without a DNS name", () => {
  it("can't be verified, and say so instead of querying", async () => {
    const h = await harness(
      { auth: new MemoryAuthStore(), sites: new MemorySiteStore() },
      { SITES_ALLOW_PRIVATE_TARGETS: "true" },
    );
    const me = await signUp(h.app);
    const site = await addSite(h.app, me, "http://127.0.0.1:8080");
    expect(site.verificationRecord).toBeNull();
    const response = await verify(h.app, me, site.id);
    expect(response.statusCode).toBe(422);
    expect(errorOf(response).code).toBe("VERIFICATION_UNSUPPORTED");
    expect(h.zone.queries).toEqual([]);
    await h.app.close();
  });
});

describe("wiring", () => {
  it("does not register the route without a verifier", async () => {
    const { app } = await createTestApp({
      env: BASE_ENV,
      auth: { store: new MemoryAuthStore(), hasher: fastHasher(), pruneIntervalMs: 0 },
      sites: { store: new MemorySiteStore() },
    });
    const me = await signUp(app);
    const site = await addSite(app, me);
    const response = await verify(app, me, site.id);
    expect(response.statusCode).toBe(404);
    expect(errorOf(response).code).toBe("NOT_FOUND");
    await app.close();
  });
});
