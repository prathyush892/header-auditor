/**
 * Binds the processor to a BullMQ `Worker`.
 *
 * - `concurrency` scans run at once per process; scale out by running more
 *   processes, since BullMQ hands each job to exactly one of them.
 * - `lockDuration` is how long a job may run before BullMQ considers the
 *   worker dead and redelivers it. It is longer than a full scan, and the
 *   claim/lease in the store makes a redelivery harmless anyway.
 * - When a job runs out of attempts, the scan is marked FAILED so the user
 *   sees a final state instead of "running" forever.
 */
import { type ConnectionOptions, type Job, Worker, type WorkerOptions } from "bullmq";
import { SCAN_QUEUE_NAME, type ScanJobData } from "@header-auditor/queue";

import { createScanProcessor, type ProcessorDeps, type ProcessOutcome } from "./processor.js";
import { ABANDONED_MESSAGE } from "./store.js";

export interface StartWorkerOptions extends ProcessorDeps {
  readonly connection: ConnectionOptions;
  readonly prefix: string;
  readonly concurrency: number;
  /** Lock time for a running job; defaults to the stale-claim window. */
  readonly lockDurationMs?: number;
  /** Retry delays in tests; BullMQ's exponential backoff otherwise. */
  readonly settings?: WorkerOptions["settings"];
}

export function startScanWorker(options: StartWorkerOptions): Worker<ScanJobData, ProcessOutcome> {
  const process = createScanProcessor(options);
  const now = options.now ?? (() => new Date());
  const { logger, store } = options;

  const worker = new Worker<ScanJobData, ProcessOutcome>(
    SCAN_QUEUE_NAME,
    (job: Job<ScanJobData, ProcessOutcome>, _token, signal) => process(job.data, signal),
    {
      connection: options.connection,
      prefix: options.prefix,
      concurrency: options.concurrency,
      lockDuration: options.lockDurationMs ?? options.staleAfterMs,
      ...(options.settings === undefined ? {} : { settings: options.settings }),
    },
  );

  worker.on("failed", (job, error) => {
    if (job === undefined) return;
    const attempts = job.opts.attempts ?? 1;
    const exhausted = job.attemptsMade >= attempts;
    logger.warn(
      { jobId: job.id, attemptsMade: job.attemptsMade, attempts, exhausted, err: error },
      "scan job failed",
    );
    if (!exhausted || typeof job.data.scanId !== "string") return;
    store.abandonScan(job.data.scanId, ABANDONED_MESSAGE, now()).catch((abandonError: unknown) => {
      logger.error({ jobId: job.id, err: abandonError }, "could not mark scan abandoned");
    });
  });

  worker.on("error", (error) => {
    // Connection problems; BullMQ keeps reconnecting.
    logger.error({ err: error }, "worker error");
  });

  return worker;
}
