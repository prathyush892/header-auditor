/**
 * The scheduler and its store, on the memory stores and on Postgres (PGlite)
 * through the Prisma stores. The queue is a MemoryScanQueue, so each test can
 * see exactly which scan ids would reach the worker.
 */
import { createPrismaClient, type PrismaClient } from "@header-auditor/db";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { createPrismaScanStore } from "../src/scans/prisma-store.js";
import { MemoryScanQueue } from "../src/scans/queue.js";
import {
  type CreateScanLimits,
  ENQUEUE_FAILED_MESSAGE,
  MemoryScanStore,
  type ScanStore,
} from "../src/scans/store.js";
import { SCHEDULE_INTERVAL_MS } from "../src/schedules/cadence.js";
import { createPrismaScheduleStore } from "../src/schedules/prisma-store.js";
import {
  createScheduler,
  type Scheduler,
  type SchedulerLogger,
  type SchedulerOptions,
} from "../src/schedules/scheduler.js";
import { MemoryScheduleStore, type ScheduleStore } from "../src/schedules/store.js";
import { createPrismaSiteStore } from "../src/sites/prisma-store.js";
import { generateVerificationToken } from "../src/sites/routes.js";
import {
  MemorySiteStore,
  type Schedule,
  type SiteRecord,
  type SiteStore,
} from "../src/sites/store.js";
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
const DAY = SCHEDULE_INTERVAL_MS.DAILY;
const RETRY_MS = 15 * 60_000;
const LIMITS: CreateScanLimits = { maxActivePerUser: 2, activeWindowMs: 15 * 60_000 };
let counter = 0;

interface Fixture {
  readonly clock: TestClock;
  readonly sites: SiteStore;
  readonly scans: ScanStore;
  readonly schedules: ScheduleStore;
  readonly usesDatabase: boolean;
  newOwner(): Promise<string>;
  markVerified(siteId: string): Promise<void>;
  /** Raw next_scan_at, bypassing the owner-scoped store. */
  nextScanAt(siteId: string): Promise<Date | null>;
  /** Every scan of a site, oldest first. */
  scansOf(siteId: string): Promise<{ id: string; status: string; trigger: string }[]>;
  finishAll(siteId: string): Promise<void>;
  /** Turns every schedule off and finishes every scan, so tests don't see each other's sites. */
  reset(): Promise<void>;
}

function memoryFixture(): Fixture {
  const clock = new TestClock();
  const sites = new MemorySiteStore(clock.now);
  const scans = new MemoryScanStore(sites, clock.now);
  const byId = (id: string): SiteRecord | undefined => sites.all().find((s) => s.id === id);
  return {
    clock,
    sites,
    scans,
    schedules: new MemoryScheduleStore(sites),
    usesDatabase: false,
    newOwner: () => Promise.resolve(crypto.randomUUID()),
    markVerified: (id) => {
      sites.markVerified(id, clock.now());
      return Promise.resolve();
    },
    nextScanAt: (id) => Promise.resolve(byId(id)?.nextScanAt ?? null),
    scansOf: (id) => Promise.resolve(scans.all().filter((s) => s.siteId === id)),
    finishAll: (id) => {
      for (const scan of scans.all()) {
        if (scan.siteId === id) scans.complete(scan.id, { status: "SUCCEEDED" });
      }
      return Promise.resolve();
    },
    reset: () => {
      for (const site of sites.all()) {
        sites.patchRecord(site.id, { schedule: "NONE", nextScanAt: null });
      }
      for (const scan of scans.all()) scans.complete(scan.id, { status: "SUCCEEDED" });
      return Promise.resolve();
    },
  };
}

function prismaFixture(): Fixture {
  const clock = new TestClock(Date.parse("2026-11-25T09:00:00.000Z"));
  return {
    clock,
    sites: createPrismaSiteStore(prisma, clock.now),
    scans: createPrismaScanStore(prisma, clock.now),
    schedules: createPrismaScheduleStore(prisma),
    usesDatabase: true,
    async newOwner() {
      counter += 1;
      const user = await prisma.user.create({
        data: { email: `sched${String(counter)}@example.test`, passwordHash: HASH },
      });
      return user.id;
    },
    async markVerified(id) {
      await prisma.site.update({ where: { id }, data: { verifiedAt: clock.now() } });
    },
    async nextScanAt(id) {
      const row = await prisma.site.findUnique({ where: { id }, select: { nextScanAt: true } });
      return row?.nextScanAt ?? null;
    },
    scansOf: (id) =>
      prisma.scan.findMany({
        where: { siteId: id },
        orderBy: { createdAt: "asc" },
        select: { id: true, status: true, trigger: true },
      }),
    async finishAll(id) {
      await prisma.scan.updateMany({
        where: { siteId: id, status: { in: ["QUEUED", "RUNNING"] } },
        data: { status: "FAILED", error: "test", finishedAt: clock.now() },
      });
    },
    async reset() {
      await prisma.site.updateMany({ data: { schedule: "NONE", nextScanAt: null } });
      await prisma.scan.updateMany({
        where: { status: { in: ["QUEUED", "RUNNING"] } },
        data: { status: "FAILED", error: "test", finishedAt: clock.now() },
      });
    },
  };
}

function silentLogger(): SchedulerLogger & { errors: string[] } {
  const errors: string[] = [];
  return {
    errors,
    info: () => undefined,
    warn: () => undefined,
    error: (_obj, msg) => errors.push(msg),
  };
}

function makeScheduler(
  fx: Fixture,
  queue: MemoryScanQueue,
  overrides: Partial<SchedulerOptions> = {},
): Scheduler {
  return createScheduler({
    schedules: fx.schedules,
    scans: fx.scans,
    queue,
    limits: LIMITS,
    logger: silentLogger(),
    batchSize: 10,
    maxBatchesPerTick: 5,
    retryDelayMs: RETRY_MS,
    intervalMs: 60_000,
    now: fx.clock.now,
    ...overrides,
  });
}

describe.each([
  ["memory stores", memoryFixture],
  ["Prisma stores (PGlite)", prismaFixture],
])("scheduler (%s)", (_name, makeFixture) => {
  let fx: Fixture;
  beforeAll(() => {
    fx = makeFixture();
  });
  afterEach(async () => {
    await fx.reset();
  });

  async function scheduledSite(
    owner: string,
    schedule: Schedule = "DAILY",
    verified = true,
  ): Promise<SiteRecord> {
    counter += 1;
    const site = await fx.sites.createSite(
      {
        ownerId: owner,
        name: `Scheduled ${String(counter)}`,
        url: `https://sched${String(counter)}.example.com`,
        verificationToken: generateVerificationToken(),
        schedule,
        firstPartyHosts: [],
      },
      100,
    );
    if (verified) await fx.markVerified(site.id);
    return site;
  }

  /** Moves the clock past every site's next run, as if a day went by. */
  function nextDay(): void {
    fx.clock.advance(DAY);
  }

  describe("ScheduleStore", () => {
    it("finds verified scheduled sites that are due, longest overdue first", async () => {
      nextDay();
      const owner = await fx.newOwner();
      const older = await scheduledSite(owner);
      fx.clock.advance(1_000);
      const newer = await scheduledSite(owner, "WEEKLY");
      await scheduledSite(owner, "DAILY", false); // not verified
      await scheduledSite(owner, "NONE"); // not scheduled
      const future = await scheduledSite(owner);
      await fx.schedules.moveNextScan(
        future.id,
        fx.clock.now(),
        new Date(fx.clock.now().getTime() + DAY),
      );

      const due = (await fx.schedules.findDueSites(fx.clock.now(), 100)).filter((s) =>
        [older.id, newer.id, future.id].includes(s.id),
      );
      expect(due.map((s) => s.id)).toEqual([older.id, newer.id]);
      expect(due[1]).toMatchObject({ ownerId: owner, schedule: "WEEKLY" });
      expect(await fx.schedules.findDueSites(fx.clock.now(), 1)).toHaveLength(1);
    });

    it("claims a run with compare-and-set: one winner, stale or cleared values lose", async () => {
      const owner = await fx.newOwner();
      const site = await scheduledSite(owner);
      const expected = site.nextScanAt;
      if (expected === null) throw new Error("expected a next run");
      const next = new Date(expected.getTime() + DAY);
      const results = await Promise.all([
        fx.schedules.moveNextScan(site.id, expected, next),
        fx.schedules.moveNextScan(site.id, expected, next),
      ]);
      expect(results.filter(Boolean)).toHaveLength(1);
      expect(await fx.nextScanAt(site.id)).toEqual(next);

      await fx.sites.updateSite(owner, site.id, { schedule: "NONE" });
      expect(await fx.schedules.moveNextScan(site.id, next, expected)).toBe(false);
      expect(await fx.nextScanAt(site.id)).toBeNull();
    });
  });

  describe("tick", () => {
    it("queues one SCHEDULED scan per due site and moves it one interval on", async () => {
      nextDay();
      const owner = await fx.newOwner();
      const site = await scheduledSite(owner);
      const queue = new MemoryScanQueue();
      const scheduler = makeScheduler(fx, queue);

      const summary = await scheduler.tick();
      expect(summary).toMatchObject({ due: 1, queued: 1, failed: 0 });
      const scans = await fx.scansOf(site.id);
      expect(scans).toMatchObject([{ status: "QUEUED", trigger: "SCHEDULED" }]);
      expect(queue.jobs).toEqual(scans.map((s) => s.id));
      expect(await fx.nextScanAt(site.id)).toEqual(new Date(fx.clock.now().getTime() + DAY));

      // Nothing is due again until the next day.
      fx.clock.advance(DAY - 60_000);
      expect((await scheduler.tick()).due).toBe(0);
      await fx.finishAll(site.id);
      fx.clock.advance(60_000);
      expect(await scheduler.tick()).toMatchObject({ due: 1, queued: 1 });
      expect(await fx.scansOf(site.id)).toHaveLength(2);
    });

    it("never scans an unverified site, even with a schedule set", async () => {
      nextDay();
      const owner = await fx.newOwner();
      const site = await scheduledSite(owner, "DAILY", false);
      const queue = new MemoryScanQueue();
      expect((await makeScheduler(fx, queue).tick()).due).toBe(0);
      expect(await fx.scansOf(site.id)).toEqual([]);
    });

    it("lets two scheduler processes share the work without double-queueing", async () => {
      nextDay();
      const owner = await fx.newOwner();
      const site = await scheduledSite(owner);
      const queue = new MemoryScanQueue();
      const [a, b] = await Promise.all([
        makeScheduler(fx, queue).tick(),
        makeScheduler(fx, queue).tick(),
      ]);
      expect(a.queued + b.queued).toBe(1);
      expect(a.claimedElsewhere + b.claimedElsewhere).toBe(a.due + b.due - 1);
      expect(await fx.scansOf(site.id)).toHaveLength(1);
      expect(queue.jobs).toHaveLength(1);
    });

    it("counts a scan that is already running as this run", async () => {
      nextDay();
      const owner = await fx.newOwner();
      const site = await scheduledSite(owner);
      const manual = await fx.scans.createScan(owner, site.id, "MANUAL", LIMITS);
      expect(manual.kind).toBe("created");
      const queue = new MemoryScanQueue();
      expect(await makeScheduler(fx, queue).tick()).toMatchObject({ alreadyRunning: 1 });
      expect(queue.jobs).toEqual([]);
      expect(await fx.nextScanAt(site.id)).toEqual(new Date(fx.clock.now().getTime() + DAY));
    });

    it("defers a run when the owner is at their active-scan limit", async () => {
      nextDay();
      const owner = await fx.newOwner();
      const busy = [await scheduledSite(owner, "NONE"), await scheduledSite(owner, "NONE")];
      for (const s of busy) {
        expect((await fx.scans.createScan(owner, s.id, "MANUAL", LIMITS)).kind).toBe("created");
      }
      const site = await scheduledSite(owner);
      const queue = new MemoryScanQueue();
      const scheduler = makeScheduler(fx, queue);
      expect(await scheduler.tick()).toMatchObject({ deferred: 1, queued: 0 });
      expect(await fx.nextScanAt(site.id)).toEqual(new Date(fx.clock.now().getTime() + RETRY_MS));

      // Once the owner's other scans finish, the retry goes through.
      for (const s of busy) await fx.finishAll(s.id);
      fx.clock.advance(RETRY_MS);
      expect(await scheduler.tick()).toMatchObject({ queued: 1 });
    });

    it("marks the scan FAILED and retries later when the queue is down", async () => {
      nextDay();
      const owner = await fx.newOwner();
      const site = await scheduledSite(owner);
      const queue = new MemoryScanQueue();
      queue.failWith = new Error("connect ECONNREFUSED 127.0.0.1:6379");
      const logger = silentLogger();
      const summary = await makeScheduler(fx, queue, { logger }).tick();
      expect(summary).toMatchObject({ failed: 1, queued: 0 });
      expect(logger.errors).toEqual(["scheduled scan failed"]);
      const [scan] = await fx.scansOf(site.id);
      expect(scan?.status).toBe("FAILED");
      if (!fx.usesDatabase) {
        expect((fx.scans as MemoryScanStore).all().find((s) => s.id === scan?.id)?.error).toBe(
          ENQUEUE_FAILED_MESSAGE,
        );
      }
      expect(await fx.nextScanAt(site.id)).toEqual(new Date(fx.clock.now().getTime() + RETRY_MS));
    });

    it("runs a long-overdue site once, not once per missed day", async () => {
      nextDay();
      const owner = await fx.newOwner();
      const site = await scheduledSite(owner);
      fx.clock.advance(5 * DAY);
      const queue = new MemoryScanQueue();
      const scheduler = makeScheduler(fx, queue);
      expect(await scheduler.tick()).toMatchObject({ queued: 1 });
      expect(await scheduler.tick()).toMatchObject({ due: 0 });
      expect(await fx.nextScanAt(site.id)).toEqual(new Date(fx.clock.now().getTime() + DAY));
    });

    it("works through more due sites than one batch, up to the per-tick cap", async () => {
      nextDay();
      const owners = await Promise.all([1, 2, 3, 4, 5].map(() => fx.newOwner()));
      const sites: SiteRecord[] = [];
      for (const owner of owners) sites.push(await scheduledSite(owner));
      const queue = new MemoryScanQueue();
      const capped = await makeScheduler(fx, queue, { batchSize: 2, maxBatchesPerTick: 2 }).tick();
      expect(capped).toMatchObject({ due: 4, queued: 4 });
      const rest = await makeScheduler(fx, queue, { batchSize: 2 }).tick();
      expect(rest).toMatchObject({ due: 1, queued: 1 });
      expect(queue.jobs).toHaveLength(5);
    });
  });
});

describe("scheduler loop", () => {
  it("ticks at start and every interval, and stop() waits for a running tick", async () => {
    vi.useFakeTimers();
    try {
      let ticks = 0;
      let release: (() => void) | undefined;
      const schedules: ScheduleStore = {
        findDueSites: () => {
          ticks += 1;
          return new Promise((resolve) => {
            release = () => {
              resolve([]);
            };
          });
        },
        moveNextScan: () => Promise.resolve(false),
      };
      const sites = new MemorySiteStore();
      const scheduler = createScheduler({
        schedules,
        scans: new MemoryScanStore(sites),
        queue: new MemoryScanQueue(),
        limits: LIMITS,
        logger: silentLogger(),
        batchSize: 10,
        maxBatchesPerTick: 1,
        retryDelayMs: RETRY_MS,
        intervalMs: 1_000,
      });
      scheduler.start();
      scheduler.start(); // idempotent while running
      expect(ticks).toBe(1);
      release?.();
      await vi.advanceTimersByTimeAsync(999);
      expect(ticks).toBe(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(ticks).toBe(2);

      let stopped = false;
      const stopping = scheduler.stop().then(() => {
        stopped = true;
      });
      await vi.advanceTimersByTimeAsync(0);
      expect(stopped).toBe(false); // tick 2 is still running
      release?.();
      await stopping;
      await vi.advanceTimersByTimeAsync(10_000);
      expect(ticks).toBe(2);
      expect(() => {
        scheduler.start();
      }).toThrow("cannot restart");
    } finally {
      vi.useRealTimers();
    }
  });

  it("logs a failed tick and keeps going", async () => {
    vi.useFakeTimers();
    try {
      let calls = 0;
      const logger = silentLogger();
      const scheduler = createScheduler({
        schedules: {
          findDueSites: () => {
            calls += 1;
            return Promise.reject(new Error("database unreachable"));
          },
          moveNextScan: () => Promise.resolve(false),
        },
        scans: new MemoryScanStore(new MemorySiteStore()),
        queue: new MemoryScanQueue(),
        limits: LIMITS,
        logger,
        batchSize: 10,
        maxBatchesPerTick: 1,
        retryDelayMs: RETRY_MS,
        intervalMs: 1_000,
      });
      scheduler.start();
      await vi.advanceTimersByTimeAsync(1_000);
      await scheduler.stop();
      expect(calls).toBe(2);
      expect(logger.errors).toEqual(["scheduler tick failed", "scheduler tick failed"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([["batchSize"], ["maxBatchesPerTick"], ["retryDelayMs"], ["intervalMs"]])(
    "refuses a non-positive %s",
    (key) => {
      const sites = new MemorySiteStore();
      expect(() =>
        createScheduler({
          schedules: new MemoryScheduleStore(sites),
          scans: new MemoryScanStore(sites),
          queue: new MemoryScanQueue(),
          limits: LIMITS,
          logger: silentLogger(),
          batchSize: 10,
          maxBatchesPerTick: 1,
          retryDelayMs: RETRY_MS,
          intervalMs: 1_000,
          [key]: 0,
        }),
      ).toThrow(RangeError);
    },
  );
});
