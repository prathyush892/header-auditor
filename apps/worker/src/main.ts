/**
 * Process entry point: config -> Postgres -> BullMQ worker, and a graceful
 * shutdown on SIGTERM/SIGINT that lets running scans finish (up to
 * WORKER_SHUTDOWN_TIMEOUT_MS) before closing connections.
 */
import { pathToFileURL } from "node:url";

import { createPrismaClient } from "@header-auditor/db";
import { redactRedisUrl, redisConnectionOptions } from "@header-auditor/queue";

import { type Env, loadWorkerConfig, WorkerConfigError } from "./config.js";
import { createLogger } from "./logger.js";
import { createPrismaWorkerStore } from "./prisma-store.js";
import { startScanWorker } from "./worker.js";

export interface RunningWorker {
  /** Idempotent: waits for active scans, then closes Redis and Postgres. */
  stop(): Promise<void>;
}

export async function main(env: Env = process.env): Promise<RunningWorker> {
  const config = loadWorkerConfig(env);
  const logger = createLogger(config.logLevel);
  const prisma = createPrismaClient({
    databaseUrl: config.databaseUrl,
    maxConnections: config.concurrency + 2,
  });
  await prisma.$connect();
  const worker = startScanWorker({
    connection: redisConnectionOptions(config.redisUrl, "consumer"),
    prefix: config.queuePrefix,
    concurrency: config.concurrency,
    staleAfterMs: config.staleAfterMs,
    store: createPrismaWorkerStore(prisma),
    logger,
    engine: { timeoutMs: config.scanTimeoutMs, allowPrivate: config.allowPrivateTargets },
  });
  await worker.waitUntilReady();
  logger.info(
    {
      redis: redactRedisUrl(config.redisUrl),
      concurrency: config.concurrency,
      allowPrivateTargets: config.allowPrivateTargets,
    },
    "worker ready",
  );

  let stopping: Promise<void> | undefined;
  return {
    stop() {
      stopping ??= (async () => {
        logger.info("shutting down: waiting for running scans");
        const timer = setTimeout(() => {
          logger.error({ timeoutMs: config.shutdownTimeoutMs }, "graceful shutdown timed out");
          process.exit(1);
        }, config.shutdownTimeoutMs);
        timer.unref();
        try {
          await worker.close();
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
      const message = error instanceof WorkerConfigError ? error.message : String(error);
      process.stderr.write(`worker failed to start: ${message}\n`);
      process.exit(1);
    },
  );
}
