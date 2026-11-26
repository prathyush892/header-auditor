/**
 * POST /sites/:id/scans, GET /sites/:id/scans (history) and
 * GET /sites/:id/scans/:scanId over HTTP.
 *
 * The authorization cases run on the memory stores and on Postgres (PGlite)
 * through the Prisma stores. The queue is a MemoryScanQueue in both, so the
 * tests can see exactly which scan ids would reach the worker.
 */
import { createPrismaClient, type PrismaClient } from "@header-auditor/db";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createPrismaAuthStore } from "../src/auth/prisma-store.js";
import { MemoryAuthStore } from "../src/auth/store.js";
import type { Env } from "../src/config.js";
import { createPrismaScanStore } from "../src/scans/prisma-store.js";
import { MemoryScanQueue } from "../src/scans/queue.js";
import { ENQUEUE_FAILED_MESSAGE, MemoryScanStore, type ScanStore } from "../src/scans/store.js";
import { createPrismaSiteStore } from "../src/sites/prisma-store.js";
import { MemorySiteStore } from "../src/sites/store.js";
import { createTestApp } from "./helpers/app.js";
import { fastHasher, ORIGIN, register, type Session, sessionFrom } from "./helpers/auth.js";
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

const ENV: Env = { AUTH_COOKIE_SECURE: "false" };
const MISSING_ID = "00000000-0000-4000-8000-000000000000";
let userCounter = 0;
let siteCounter = 0;

interface Harness {
  readonly app: FastifyInstance;
  readonly queue: MemoryScanQueue;
  readonly scans: ScanStore;
}

async function memoryHarness(env: Env = {}): Promise<Harness> {
  const sites = new MemorySiteStore();
  const scans = new MemoryScanStore(sites);
  const queue = new MemoryScanQueue();
  const { app } = await createTestApp({
    env: { ...ENV, ...env },
    auth: { store: new MemoryAuthStore(), hasher: fastHasher(), pruneIntervalMs: 0 },
    sites: { store: sites },
    scans: { store: scans, queue },
  });
  return { app, queue, scans };
}

async function prismaHarness(env: Env = {}): Promise<Harness> {
  const scans = createPrismaScanStore(prisma);
  const queue = new MemoryScanQueue();
  const { app } = await createTestApp({
    env: { ...ENV, ...env },
    auth: { store: createPrismaAuthStore(prisma), hasher: fastHasher(), pruneIntervalMs: 0 },
    sites: { store: createPrismaSiteStore(prisma) },
    scans: { store: scans, queue },
  });
  return { app, queue, scans };
}

async function signUp(app: FastifyInstance): Promise<Session> {
  userCounter += 1;
  const response = await register(app, `scans${String(userCounter)}@example.test`);
  expect(response.statusCode).toBe(201);
  return sessionFrom(response);
}

function call(
  app: FastifyInstance,
  session: Session | null,
  method: "GET" | "POST",
  url: string,
  options: { payload?: unknown; headers?: Record<string, string> } = {},
): Promise<LightMyRequestResponse> {
  return app.inject({
    method,
    url,
    headers: {
      origin: ORIGIN,
      ...(session === null ? {} : { cookie: session.cookie, "x-csrf-token": session.csrfToken }),
      ...options.headers,
    },
    ...(options.payload === undefined
      ? {}
      : { payload: options.payload as Record<string, unknown> }),
  });
}

async function addSite(
  app: FastifyInstance,
  session: Session,
): Promise<{ id: string; url: string }> {
  siteCounter += 1;
  const response = await call(app, session, "POST", "/sites", {
    payload: { name: "Blog", url: `blog${String(siteCounter)}.example.com` },
  });
  expect(response.statusCode, response.body).toBe(201);
  return response.json();
}

function startScan(app: FastifyInstance, session: Session | null, siteId: string) {
  return call(app, session, "POST", `/sites/${siteId}/scans`);
}

function errorCode(response: LightMyRequestResponse): string {
  return response.json<{ error: { code: string } }>().error.code;
}

describe.each([
  ["memory stores", memoryHarness],
  ["Prisma stores (PGlite)", prismaHarness],
])("authorization (%s)", (_name, makeHarness) => {
  let h: Harness;
  let alice: Session;
  let bob: Session;
  let aliceSite: { id: string; url: string };

  beforeAll(async () => {
    h = await makeHarness();
    alice = await signUp(h.app);
    bob = await signUp(h.app);
    aliceSite = await addSite(h.app, alice);
  });

  afterAll(async () => {
    await h.app.close();
  });

  it("queues a scan for the owner: 202, Location, and exactly one job", async () => {
    const response = await startScan(h.app, alice, aliceSite.id);
    expect(response.statusCode, response.body).toBe(202);
    const scan = response.json<Record<string, unknown> & { id: string }>();
    expect(scan).toMatchObject({
      siteId: aliceSite.id,
      status: "queued",
      trigger: "manual",
      requestedUrl: aliceSite.url,
      score: null,
      grade: null,
      finishedAt: null,
    });
    expect(response.headers.location).toBe(`/sites/${aliceSite.id}/scans/${scan.id}`);
    expect(h.queue.jobs).toEqual([scan.id]);

    const poll = await call(h.app, alice, "GET", String(response.headers.location));
    expect(poll.statusCode).toBe(200);
    expect(poll.json()).toMatchObject({
      id: scan.id,
      status: "queued",
      findings: [],
      report: null,
    });
  });

  it("gives Bob the same 404 for Alice's site as for a site that doesn't exist", async () => {
    const theirs = await startScan(h.app, bob, aliceSite.id);
    const missing = await startScan(h.app, bob, MISSING_ID);
    expect(theirs.statusCode).toBe(404);
    expect(theirs.json<{ error: { message: string } }>().error.message).toBe(
      missing.json<{ error: { message: string } }>().error.message,
    );
    expect(errorCode(theirs)).toBe("SITE_NOT_FOUND");
    expect(errorCode(missing)).toBe("SITE_NOT_FOUND");
  });

  it("never lets Bob read Alice's scan, even through his own site's URL", async () => {
    const [scanId] = h.queue.jobs;
    expect(scanId).toBeDefined();
    const bobSite = await addSite(h.app, bob);
    for (const url of [
      `/sites/${aliceSite.id}/scans/${String(scanId)}`,
      `/sites/${bobSite.id}/scans/${String(scanId)}`,
    ]) {
      const response = await call(h.app, bob, "GET", url);
      expect(response.statusCode).toBe(404);
      expect(errorCode(response)).toBe("SCAN_NOT_FOUND");
    }
  });

  it("gives Bob a 404 for Alice's scan history, like a missing site", async () => {
    for (const id of [aliceSite.id, MISSING_ID, "not-a-uuid"]) {
      const response = await call(h.app, bob, "GET", `/sites/${id}/scans`);
      expect(response.statusCode).toBe(404);
      expect(errorCode(response)).toBe("SITE_NOT_FOUND");
    }
    const own = await call(h.app, alice, "GET", `/sites/${aliceSite.id}/scans`);
    expect(own.statusCode).toBe(200);
    expect(own.json<{ items: { id: string }[] }>().items.map((s) => s.id)).toEqual(h.queue.jobs);
  });

  it("requires a session", async () => {
    expect((await call(h.app, null, "GET", `/sites/${aliceSite.id}/scans`)).statusCode).toBe(401);
    expect((await startScan(h.app, null, aliceSite.id)).statusCode).toBe(401);
    const response = await call(h.app, null, "GET", `/sites/${aliceSite.id}/scans/${MISSING_ID}`);
    expect(response.statusCode).toBe(401);
  });
});

describe("POST /sites/:id/scans", () => {
  let h: Harness;
  let session: Session;

  beforeAll(async () => {
    h = await memoryHarness({ SCANS_MAX_ACTIVE_PER_USER: "2" });
    session = await signUp(h.app);
  });

  afterAll(async () => {
    await h.app.close();
  });

  it("answers 409 with the running scan's Location instead of queueing a second one", async () => {
    const site = await addSite(h.app, session);
    const first = await startScan(h.app, session, site.id);
    const second = await startScan(h.app, session, site.id);
    expect(second.statusCode).toBe(409);
    expect(errorCode(second)).toBe("SCAN_IN_PROGRESS");
    expect(second.headers.location).toBe(first.headers.location);
    expect(h.queue.jobs).toHaveLength(1);
  });

  it("answers 429 at the per-user active-scan limit", async () => {
    const site = await addSite(h.app, session);
    expect((await startScan(h.app, session, site.id)).statusCode).toBe(202);
    const third = await startScan(h.app, session, (await addSite(h.app, session)).id);
    expect(third.statusCode).toBe(429);
    expect(errorCode(third)).toBe("SCAN_LIMIT_REACHED");
    expect(third.json<{ error: { message: string } }>().error.message).toContain("2 scans");
  });

  it("rejects a request without the CSRF token", async () => {
    const site = await addSite(h.app, session);
    const response = await h.app.inject({
      method: "POST",
      url: `/sites/${site.id}/scans`,
      headers: { origin: ORIGIN, cookie: session.cookie },
    });
    expect(response.statusCode).toBe(403);
  });

  it("rejects a body, since no options exist yet", async () => {
    const site = await addSite(h.app, session);
    const response = await call(h.app, session, "POST", `/sites/${site.id}/scans`, {
      payload: { url: "http://169.254.169.254/" },
    });
    expect(response.statusCode).toBe(400);
    expect(errorCode(response)).toBe("VALIDATION_FAILED");
  });

  it.each(["not-a-uuid", "../sites", MISSING_ID.toUpperCase()])(
    "treats a malformed or unknown site id (%s) as 404",
    async (id) => {
      const response = await startScan(h.app, session, encodeURIComponent(id));
      expect(response.statusCode).toBe(404);
    },
  );
});

describe("when the queue is down", () => {
  it("answers 503, marks the scan FAILED and leaves the site free to retry", async () => {
    const h = await memoryHarness();
    const session = await signUp(h.app);
    const site = await addSite(h.app, session);
    h.queue.failWith = new Error("connect ECONNREFUSED 127.0.0.1:6379");

    const response = await startScan(h.app, session, site.id);
    expect(response.statusCode).toBe(503);
    expect(errorCode(response)).toBe("QUEUE_UNAVAILABLE");
    // The Redis error is logged, never sent to the client.
    expect(response.body).not.toContain("ECONNREFUSED");
    const [failed] = (h.scans as MemoryScanStore).all();
    expect(failed).toMatchObject({ status: "FAILED", error: ENQUEUE_FAILED_MESSAGE });

    h.queue.failWith = undefined;
    expect((await startScan(h.app, session, site.id)).statusCode).toBe(202);
    await h.app.close();
  });
});

describe("GET /sites/:id/scans (history)", () => {
  interface Page {
    items: (Record<string, unknown> & { id: string; createdAt: string })[];
    nextCursor: string | null;
  }

  let h: Harness;
  let session: Session;
  let site: { id: string; url: string };
  const ids: string[] = [];

  beforeAll(async () => {
    h = await memoryHarness();
    session = await signUp(h.app);
    site = await addSite(h.app, session);
    for (let n = 0; n < 5; n += 1) {
      const scan = (await startScan(h.app, session, site.id)).json<{ id: string }>();
      await h.scans.failQueuedScan(scan.id, "done", new Date());
      ids.push(scan.id);
    }
  });

  afterAll(async () => {
    await h.app.close();
  });

  const list = (query = "") => call(h.app, session, "GET", `/sites/${site.id}/scans${query}`);

  it("returns summaries newest first, without findings or the report", async () => {
    const response = await list();
    expect(response.statusCode).toBe(200);
    const page = response.json<Page>();
    expect(page.nextCursor).toBeNull();
    expect(page.items).toHaveLength(5);
    const times = page.items.map((s) => Date.parse(s.createdAt));
    expect([...times].sort((a, b) => b - a)).toEqual(times);
    expect(new Set(page.items.map((s) => s.id))).toEqual(new Set(ids));
    expect(page.items[0]).toMatchObject({ siteId: site.id, status: "failed", trigger: "manual" });
    expect(page.items[0]).not.toHaveProperty("findings");
    expect(page.items[0]).not.toHaveProperty("report");
  });

  it("walks every scan exactly once with ?limit and ?cursor", async () => {
    const all = (await list()).json<Page>().items.map((s) => s.id);
    const seen: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const query: string = `?limit=2${cursor === null ? "" : `&cursor=${cursor}`}`;
      const page: Page = (await list(query)).json<Page>();
      seen.push(...page.items.map((s) => s.id));
      cursor = page.nextCursor;
      pages += 1;
    } while (cursor !== null);
    expect(seen).toEqual(all);
    expect(pages).toBe(3);
  });

  it("returns an empty page for a site that has never been scanned", async () => {
    const fresh = await addSite(h.app, session);
    const response = await call(h.app, session, "GET", `/sites/${fresh.id}/scans`);
    expect(response.json()).toEqual({ items: [], nextCursor: null });
  });

  it.each([
    ["?limit=0", "limit"],
    ["?limit=101", "limit"],
    ["?limit=abc", "limit"],
    ["?cursor=not-a-cursor", "cursor"],
    ["?status=failed", ""],
  ])("rejects %s with a 400", async (query, path) => {
    const response = await list(query);
    expect(response.statusCode).toBe(400);
    expect(errorCode(response)).toBe("VALIDATION_FAILED");
    if (path !== "") {
      const details = response.json<{ error: { details: { path: string }[] } }>().error.details;
      expect(details.map((d) => d.path)).toContain(path);
    }
  });
});

describe("GET /sites/:id/scans/:scanId", () => {
  it("returns a finished scan with lower-cased enums and ordered findings", async () => {
    const h = await memoryHarness();
    const session = await signUp(h.app);
    const site = await addSite(h.app, session);
    const queued = (await startScan(h.app, session, site.id)).json<{ id: string }>();
    const finished = new Date("2026-11-24T12:00:05.000Z");
    (h.scans as MemoryScanStore).complete(queued.id, {
      status: "SUCCEEDED",
      score: 92,
      grade: "A",
      httpStatus: 200,
      finalUrl: `${site.url}/`,
      engineVersion: "0.0.0",
      startedAt: new Date("2026-11-24T12:00:00.000Z"),
      finishedAt: finished,
      report: { headers: { score: 92 } },
      findings: [
        {
          category: "HEADERS",
          check: "Strict-Transport-Security",
          status: "PASS",
          detail: "max-age=63072000",
          weight: 15,
          score: 15,
          recommendation: "",
          position: 0,
        },
      ],
    });
    const response = await call(h.app, session, "GET", `/sites/${site.id}/scans/${queued.id}`);
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      status: "succeeded",
      grade: "A",
      score: 92,
      finishedAt: finished.toISOString(),
      report: { headers: { score: 92 } },
      findings: [{ category: "headers", status: "pass", check: "Strict-Transport-Security" }],
    });
    // Internal fields stay internal.
    expect(response.json()).not.toHaveProperty("findings.0.position");
    await h.app.close();
  });
});

describe("buildApp", () => {
  it("refuses scans without sites", async () => {
    const sites = new MemorySiteStore();
    await expect(
      createTestApp({
        auth: { store: new MemoryAuthStore(), hasher: fastHasher(), pruneIntervalMs: 0 },
        scans: { store: new MemoryScanStore(sites), queue: new MemoryScanQueue() },
      }),
    ).rejects.toThrow("`scans` requires `sites`");
  });
});
