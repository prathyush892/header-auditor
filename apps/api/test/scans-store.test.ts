/**
 * The ScanStore contract, run against MemoryScanStore and the Prisma store on
 * PGlite. The ownership and limit rules are checked here, at the layer that
 * enforces them, as well as through HTTP in scans-routes.test.ts.
 */
import { createPrismaClient, type PrismaClient } from "@header-auditor/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createPrismaScanStore, type PrismaScanClient } from "../src/scans/prisma-store.js";
import {
  type CreateScanLimits,
  type CreateScanResult,
  MemoryScanStore,
  type ScanRecord,
  type ScanStore,
  STALE_SCAN_MESSAGE,
} from "../src/scans/store.js";
import { createPrismaSiteStore } from "../src/sites/prisma-store.js";
import { generateVerificationToken } from "../src/sites/routes.js";
import { MemorySiteStore, type SiteStore } from "../src/sites/store.js";
import { TestClock } from "./helpers/auth.js";
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

const HASH = "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g";
const MISSING_ID = "00000000-0000-4000-8000-000000000000";
const LIMITS: CreateScanLimits = { maxActivePerUser: 3, activeWindowMs: 15 * 60_000 };
let counter = 0;

interface Fixture {
  readonly sites: SiteStore;
  readonly scans: ScanStore;
  readonly clock: TestClock;
  readonly usesDatabase: boolean;
}

function memoryFixture(): Fixture {
  const clock = new TestClock();
  const sites = new MemorySiteStore(clock.now);
  return { sites, scans: new MemoryScanStore(sites, clock.now), clock, usesDatabase: false };
}

function prismaFixture(): Fixture {
  const clock = new TestClock(Date.now());
  return {
    sites: createPrismaSiteStore(prisma),
    scans: createPrismaScanStore(prisma, clock.now),
    clock,
    usesDatabase: true,
  };
}

async function newOwner(fx: Fixture): Promise<string> {
  counter += 1;
  if (!fx.usesDatabase) return crypto.randomUUID();
  const user = await prisma.user.create({
    data: { email: `scanowner${String(counter)}@example.test`, passwordHash: HASH },
  });
  return user.id;
}

async function newSite(fx: Fixture, ownerId: string): Promise<{ id: string; url: string }> {
  counter += 1;
  return fx.sites.createSite(
    {
      ownerId,
      name: `Scan site ${String(counter)}`,
      url: `https://scan${String(counter)}.example.com`,
      verificationToken: generateVerificationToken(),
      schedule: "NONE",
      firstPartyHosts: [],
    },
    100,
  );
}

function created(result: CreateScanResult): ScanRecord {
  if (result.kind !== "created") throw new Error(`expected created, got ${result.kind}`);
  return result.scan;
}

describe.each([
  ["MemoryScanStore", memoryFixture],
  ["Prisma store (PGlite)", prismaFixture],
])("%s", (_name, makeFixture) => {
  let fx: Fixture;
  beforeAll(() => {
    fx = makeFixture();
  });

  it("creates a QUEUED scan that copies the site's URL", async () => {
    const owner = await newOwner(fx);
    const site = await newSite(fx, owner);
    const scan = created(await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS));
    expect(scan).toMatchObject({
      siteId: site.id,
      status: "QUEUED",
      trigger: "MANUAL",
      requestedUrl: site.url,
      finalUrl: null,
      score: null,
      grade: null,
      error: null,
      startedAt: null,
      finishedAt: null,
    });
    const detail = await fx.scans.findScan(owner, site.id, scan.id);
    expect(detail).toMatchObject({ id: scan.id, report: null, findings: [] });
  });

  it("refuses to scan someone else's site, the same way as a missing one", async () => {
    const alice = await newOwner(fx);
    const bob = await newOwner(fx);
    const site = await newSite(fx, alice);
    expect(await fx.scans.createScan(bob, site.id, "MANUAL", LIMITS)).toEqual({
      kind: "site_not_found",
    });
    expect(await fx.scans.createScan(bob, MISSING_ID, "MANUAL", LIMITS)).toEqual({
      kind: "site_not_found",
    });
  });

  it("hides a scan from everyone but the site's owner", async () => {
    const alice = await newOwner(fx);
    const bob = await newOwner(fx);
    const site = await newSite(fx, alice);
    const bobSite = await newSite(fx, bob);
    const scan = created(await fx.scans.createScan(alice, site.id, "MANUAL", LIMITS));
    expect(await fx.scans.findScan(bob, site.id, scan.id)).toBeNull();
    // Right scan id, but routed through Bob's own site: still nothing.
    expect(await fx.scans.findScan(bob, bobSite.id, scan.id)).toBeNull();
    expect(await fx.scans.findScan(alice, bobSite.id, scan.id)).toBeNull();
    expect(await fx.scans.findScan(alice, site.id, MISSING_ID)).toBeNull();
  });

  it("allows one active scan per site and points at it", async () => {
    const owner = await newOwner(fx);
    const site = await newSite(fx, owner);
    const first = created(await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS));
    const second = await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS);
    expect(second.kind).toBe("in_progress");
    expect(second.kind === "in_progress" && second.scan.id).toBe(first.id);
  });

  it("caps active scans per user across sites, without counting other users", async () => {
    const owner = await newOwner(fx);
    const other = await newOwner(fx);
    const limits = { ...LIMITS, maxActivePerUser: 2 };
    created(await fx.scans.createScan(other, (await newSite(fx, other)).id, "MANUAL", limits));
    created(await fx.scans.createScan(owner, (await newSite(fx, owner)).id, "MANUAL", limits));
    created(await fx.scans.createScan(owner, (await newSite(fx, owner)).id, "MANUAL", limits));
    const third = await fx.scans.createScan(owner, (await newSite(fx, owner)).id, "MANUAL", limits);
    expect(third).toEqual({ kind: "limit_reached", limit: 2 });
  });

  it("frees the site once the active scan fails to enqueue", async () => {
    const owner = await newOwner(fx);
    const site = await newSite(fx, owner);
    const scan = created(await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS));
    const at = fx.clock.now();
    await fx.scans.failQueuedScan(scan.id, "could not queue", at);
    const detail = await fx.scans.findScan(owner, site.id, scan.id);
    expect(detail).toMatchObject({ status: "FAILED", error: "could not queue" });
    expect(detail?.finishedAt?.getTime()).toBe(at.getTime());
    created(await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS));
  });

  it("abandons a stale queued scan after the active window instead of blocking the site", async () => {
    const owner = await newOwner(fx);
    const site = await newSite(fx, owner);
    const stale = created(await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS));
    fx.clock.advance(LIMITS.activeWindowMs + 1_000);
    const fresh = created(await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS));
    expect(fresh.id).not.toBe(stale.id);
    expect(await fx.scans.findScan(owner, site.id, stale.id)).toMatchObject({
      status: "FAILED",
      error: STALE_SCAN_MESSAGE,
    });
  });

  it("serialises concurrent requests for one site into a single scan", async () => {
    const owner = await newOwner(fx);
    const site = await newSite(fx, owner);
    const results = await Promise.all(
      Array.from({ length: 5 }, () => fx.scans.createScan(owner, site.id, "MANUAL", LIMITS)),
    );
    expect(results.filter((r) => r.kind === "created")).toHaveLength(1);
    expect(results.filter((r) => r.kind === "in_progress")).toHaveLength(4);
  });
});

describe("Prisma store only", () => {
  it("turns a lost insert race into in_progress (the partial unique index backstop)", async () => {
    const fx = prismaFixture();
    const owner = await newOwner(fx);
    const site = await newSite(fx, owner);
    const first = created(await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS));
    // Simulate a request that checked before `first` was committed: its
    // "is anything active?" query sees nothing, so it goes on to insert.
    let hideActive = true;
    const racy: PrismaScanClient = {
      scan: prisma.scan,
      $transaction: (fn) =>
        prisma.$transaction((tx) =>
          fn({
            site: tx.site,
            $queryRaw: (query, ...values) => tx.$queryRaw(query, ...values),
            scan: {
              findMany: (args) => {
                if (hideActive) {
                  hideActive = false;
                  return Promise.resolve([]);
                }
                return tx.scan.findMany(args);
              },
              findFirst: (args) => tx.scan.findFirst(args),
              count: (args) => tx.scan.count(args),
              create: (args) => tx.scan.create(args),
              updateMany: (args) => tx.scan.updateMany(args),
            },
          }),
        ),
    };
    const result = await createPrismaScanStore(racy, fx.clock.now).createScan(
      owner,
      site.id,
      "MANUAL",
      LIMITS,
    );
    expect(hideActive).toBe(false);
    expect(result.kind === "in_progress" && result.scan.id).toBe(first.id);
  });

  it("leaves a scan alone once a worker has moved it past QUEUED", async () => {
    const fx = prismaFixture();
    const owner = await newOwner(fx);
    const site = await newSite(fx, owner);
    const scan = created(await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS));
    await prisma.scan.update({
      where: { id: scan.id },
      data: { status: "RUNNING", startedAt: new Date() },
    });
    await fx.scans.failQueuedScan(scan.id, "late failure", new Date());
    expect(await prisma.scan.findUniqueOrThrow({ where: { id: scan.id } })).toMatchObject({
      status: "RUNNING",
      error: null,
    });
  });

  it("returns findings in engine order with the stored report", async () => {
    const fx = prismaFixture();
    const owner = await newOwner(fx);
    const site = await newSite(fx, owner);
    const scan = created(await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS));
    const finding = {
      category: "HEADERS",
      status: "PASS",
      detail: "ok",
      weight: 10,
      score: 10,
    } as const;
    await prisma.scan.update({
      where: { id: scan.id },
      data: {
        status: "SUCCEEDED",
        score: 100,
        grade: "A",
        startedAt: new Date(),
        finishedAt: new Date(),
        report: { headers: { grade: "A" } },
        findings: {
          create: [
            { ...finding, check: "second", position: 1 },
            { ...finding, check: "first", position: 0 },
          ],
        },
      },
    });
    const detail = await fx.scans.findScan(owner, site.id, scan.id);
    expect(detail?.findings.map((f) => f.check)).toEqual(["first", "second"]);
    expect(detail?.report).toEqual({ headers: { grade: "A" } });
  });

  it("drops a site's scans with the site (ON DELETE CASCADE)", async () => {
    const fx = prismaFixture();
    const owner = await newOwner(fx);
    const site = await newSite(fx, owner);
    const scan = created(await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS));
    expect(await fx.sites.deleteSite(owner, site.id)).toBe(true);
    expect(await prisma.scan.findUnique({ where: { id: scan.id } })).toBeNull();
  });
});
