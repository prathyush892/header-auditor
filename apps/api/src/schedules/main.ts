/**
 * Scheduler process: config -> Postgres + BullMQ producer -> tick loop, with
 * a graceful shutdown on SIGTERM/SIGINT that lets a running tick finish.
 *
 *   node apps/api/dist/schedules/main.js
 *
 * It runs separately from the API so web replicas can scale without each
 * one also scheduling, and it is safe to run more than one (claims are
 * compare-and-set), which a rolling deploy does for a moment.
 */
import { pathToFileURL } from "node:url";

import { createPrismaClient } from "@header-auditor/db";
import { redactRedisUrl, redisConnectionOptions, SCAN_QUEUE_NAME } from "@header-auditor/queue";
import { Queue } from "bullmq";
import { pino } from "pino";

import type { Env } from "../config.js";
import { createPrismaScanStore } from "../scans/prisma-store.js";
import { createBullScanQueue } from "../scans/queue.js";
import { loadSchedulerConfig, SchedulerConfigError } from "./config.js";
import { createPrismaScheduleStore } from "./prisma-store.js";
import { createScheduler } from "./scheduler.js";

export interface RunningScheduler {
  /** Idempotent: waits for the current tick, then closes Redis and Postgres. */
  stop(): Promise<void>;
}

export async function main(env: Env = process.env): Promise<RunningScheduler> {
  const config = loadSchedulerConfig(env);
  const logger = pino({
    level: config.logLevel,
    base: { service: "scheduler" },
    redact: { paths: ["*.password", "*.databaseUrl", "*.redisUrl"], censor: "[REDACTED]" },
  });
  const prisma = createPrismaClient({ databaseUrl: config.databaseUrl, maxConnections: 2 });
  await prisma.$connect();
  const queue = new Queue(SCAN_QUEUE_NAME, {
    connection: redisConnectionOptions(config.redisUrl, "producer"),
    prefix: config.queuePrefix,
  });
  await queue.waitUntilReady();

  const scheduler = createScheduler({
    schedules: createPrismaScheduleStore(prisma),
    scans: createPrismaScanStore(prisma),
    queue: createBullScanQueue(queue),
    limits: config.limits,
    logger,
    batchSize: config.batchSize,
    maxBatchesPerTick: config.maxBatchesPerTick,
    retryDelayMs: config.retryDelayMs,
    intervalMs: config.intervalMs,
  });
  scheduler.start();
  logger.info(
    { redis: redactRedisUrl(config.redisUrl), intervalMs: config.intervalMs },
    "scheduler ready",
  );

  let stopping: Promise<void> | undefined;
  return {
    stop() {
      stopping ??= (async () => {
        logger.info("shutting down: waiting for the current tick");
        const timer = setTimeout(() => {
          logger.error({ timeoutMs: config.shutdownTimeoutMs }, "graceful shutdown timed out");
          process.exit(1);
        }, config.shutdownTimeoutMs);
        timer.unref();
        try {
          await scheduler.stop();
          await queue.close();
          await prisma.$disconnect();
        } finally {
          clearTimeout(timer);
        }
      })();
      return stopping;
    },
  };
}

function isMainModule(): boolean {
  const entry = process.argv[1];
  return entry !== undefined && import.meta.url === pathToFileURL(entry).href;
}

if (isMainModule()) {
  main().then(
    (running) => {
      for (const signal of ["SIGTERM", "SIGINT"] as const) {
        process.once(signal, () => {
          running.stop().then(
            () => process.exit(0),
            () => process.exit(1),
          );
        });
      }
    },
    (error: unknown) => {
      const message = error instanceof SchedulerConfigError ? error.message : String(error);
      process.stderr.write(`scheduler failed to start: ${message}\n`);
      process.exit(1);
    },
  );
}
