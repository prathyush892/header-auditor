/**
 * The whole pipeline with real parts: the API (Prisma stores on PGlite)
 * enqueues through BullMQ on a real Redis, this worker consumes the job, runs
 * the real engine against a mock site on 127.0.0.1, and the API serves the
 * stored result. Only loopback is ever contacted.
 */
import {
  buildApp,
  createBullScanQueue,
  createPrismaAuthStore,
  createPrismaScanStore,
  createPrismaSiteStore,
  createPasswordHasher,
  loadConfig,
} from "@header-auditor/api";
import { createPrismaClient, type PrismaClient } from "@header-auditor/db";
import {
  parseScanJobData,
  redisConnectionOptions,
  SCAN_JOB_ATTEMPTS,
  SCAN_QUEUE_NAME,
  type ScanJobData,
} from "@header-auditor/queue";
import { Queue, QueueEvents, type Worker } from "bullmq";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createPrismaWorkerStore } from "../src/prisma-store.js";
import type { ProcessOutcome } from "../src/processor.js";
import { ABANDONED_MESSAGE } from "../src/store.js";
import { startScanWorker } from "../src/worker.js";
import { startTestDatabase, type TestDatabase } from "./helpers/database.js";
import { TestLogger } from "./helpers/fixtures.js";
import { startTestRedis, type TestRedis } from "./helpers/redis.js";
import { type MockSite, startHttpSite } from "./helpers/servers.js";

const ORIGIN = "http://localhost:3000";

let db: TestDatabase;
let redis: TestRedis;
let prisma: PrismaClient;
let site: MockSite;
let queue: Queue<ScanJobData>;
let events: QueueEvents;
let worker: Worker<ScanJobData, ProcessOutcome>;
let app: FastifyInstance;
let cookie: string;
let csrf: string;
const logger = new TestLogger();

beforeAll(async () => {
  [db, redis, site] = await Promise.all([startTestDatabase(), startTestRedis(), startHttpSite()]);
  expect(new URL(redis.url).hostname).toBe("127.0.0.1");
  prisma = createPrismaClient({ databaseUrl: db.url, maxConnections: 4 });

  const producer = redisConnectionOptions(redis.url, "producer");
  queue = new Queue<ScanJobData>(SCAN_QUEUE_NAME, { connection: producer, prefix: redis.prefix });
  events = new QueueEvents(SCAN_QUEUE_NAME, {
    connection: redisConnectionOptions(redis.url, "consumer"),
    prefix: redis.prefix,
  });
  await events.waitUntilReady();

  worker = startScanWorker({
    connection: redisConnectionOptions(redis.url, "consumer"),
    prefix: redis.prefix,
    concurrency: 2,
    staleAfterMs: 60_000,
    store: createPrismaWorkerStore(prisma),
    logger,
    engine: { timeoutMs: 5_000, allowPrivate: true },
    // Retry immediately so the "out of attempts" test doesn't wait for backoff.
    settings: { backoffStrategy: () => 0 },
  });
  await worker.waitUntilReady();

  app = await buildApp({
    config: loadConfig({
      NODE_ENV: "test",
      LOG_LEVEL: "silent",
      AUTH_COOKIE_SECURE: "false",
      SITES_ALLOW_PRIVATE_TARGETS: "true",
    }),
    auth: {
      store: createPrismaAuthStore(prisma),
      hasher: createPasswordHasher({ memoryCost: 64, timeCost: 1, parallelism: 1 }),
      pruneIntervalMs: 0,
    },
    sites: { store: createPrismaSiteStore(prisma) },
    scans: { store: createPrismaScanStore(prisma), queue: createBullScanQueue(queue) },
  });
  const registered = await app.inject({
    method: "POST",
    url: "/auth/register",
    headers: { origin: ORIGIN },
    payload: { email: "pipeline@example.test", password: "correct horse battery staple" },
  });
  expect(registered.statusCode).toBe(201);
  const setCookie = registered.headers["set-cookie"];
  cookie = String(Array.isArray(setCookie) ? setCookie[0] : setCookie).split(";")[0] ?? "";
  csrf = registered.json<{ csrfToken: string }>().csrfToken;
});

afterAll(async () => {
  await app.close();
  await worker.close();
  await events.close();
  await queue.obliterate({ force: true });
  await queue.close();
  await prisma.$disconnect();
  await Promise.all([db.stop(), redis.stop(), site.close()]);
});

function api(
  method: "GET" | "POST",
  url: string,
  payload?: object,
): Promise<LightMyRequestResponse> {
  return app.inject({
    method,
    url,
    headers: { origin: ORIGIN, cookie, "x-csrf-token": csrf },
    ...(payload === undefined ? {} : { payload }),
  });
}

async function poll(location: string, until: (status: string) => boolean) {
  const deadline = Date.now() + 15_000;
  for (;;) {
    const response = await api("GET", location);
    const body = response.json<{ status: string }>();
    if (until(body.status) || Date.now() > deadline) return response;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

describe("scan pipeline", () => {
  it("queues, runs and stores a scan of a mock site", async () => {
    const created = await api("POST", "/sites", {
      name: "Mock shop",
      url: `http://127.0.0.1:${String(site.port)}`,
    });
    expect(created.statusCode, created.body).toBe(201);
    const { id: siteId } = created.json<{ id: string }>();

    const queued = await api("POST", `/sites/${siteId}/scans`);
    expect(queued.statusCode, queued.body).toBe(202);
    const scanId = queued.json<{ id: string }>().id;

    // The job on Redis carries the id and nothing else.
    const job = await queue.getJob(scanId);
    expect(job?.name).toBe("scan");
    expect(parseScanJobData(job?.data)).toEqual({ scanId });
    expect(job?.opts.attempts).toBe(SCAN_JOB_ATTEMPTS);

    const done = await poll(
      String(queued.headers.location),
      (s) => s !== "queued" && s !== "running",
    );
    const scan = done.json<{
      status: string;
      grade: string;
      score: number;
      httpStatus: number;
      findings: { category: string }[];
      report: { tls: { status: string }; wellKnown: { status: string } };
    }>();
    expect(scan.status).toBe("succeeded");
    expect(scan.httpStatus).toBe(200);
    expect(scan.grade).toMatch(/^[A-F]$/);
    expect(new Set(scan.findings.map((f) => f.category))).toEqual(
      new Set(["headers", "content", "well_known"]),
    );
    expect(scan.report.tls.status).toBe("skipped");
    expect(scan.report.wellKnown.status).toBe("ok");
    expect(site.requests).toContain("/");

    // The site is free again once the scan is done.
    expect((await api("POST", `/sites/${siteId}/scans`)).statusCode).toBe(202);
  });

  it("ignores a duplicate job for the same scan (job id = scan id)", async () => {
    const created = await api("POST", "/sites", {
      name: "Dup",
      url: `http://localhost:${String(site.port)}`,
    });
    const { id: siteId } = created.json<{ id: string }>();
    const queued = await api("POST", `/sites/${siteId}/scans`);
    const scanId = queued.json<{ id: string }>().id;
    // A retried enqueue (e.g. a replayed request) adds nothing.
    await createBullScanQueue(queue).enqueue(scanId);
    const jobs = await queue.getJobs(["waiting", "active", "completed", "delayed"]);
    expect(jobs.filter((j) => j.id === scanId)).toHaveLength(1);
    await poll(String(queued.headers.location), (s) => s === "succeeded" || s === "failed");
  });

  it("marks a scan FAILED once its job runs out of attempts", async () => {
    // Every attempt of this job throws: its payload has a key the worker
    // refuses. After the last attempt the `failed` handler closes the scan.
    const created = await api("POST", "/sites", { name: "Doomed", url: "http://127.0.0.2:9" });
    const { id: siteId } = created.json<{ id: string }>();
    const scan = await prisma.scan.create({
      data: { siteId, requestedUrl: "http://127.0.0.2:9", status: "QUEUED" },
    });
    const job = await queue.add(
      "scan",
      { scanId: scan.id, extra: "rejected by the payload check" } as unknown as ScanJobData,
      { jobId: scan.id, attempts: 2 },
    );
    await job.waitUntilFinished(events).catch(() => undefined);
    const deadline = Date.now() + 5_000;
    let row = await prisma.scan.findUniqueOrThrow({ where: { id: scan.id } });
    while (row.status !== "FAILED" && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      row = await prisma.scan.findUniqueOrThrow({ where: { id: scan.id } });
    }
    expect(row).toMatchObject({ status: "FAILED", error: ABANDONED_MESSAGE });
    expect(logger.messages()).toContain("scan job failed");
  });
});
