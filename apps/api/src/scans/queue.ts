/**
 * The producer side of the scan queue.
 *
 * Routes depend on the small `ScanQueue` interface; `createBullScanQueue`
 * adapts a BullMQ `Queue`. Tests use `MemoryScanQueue`, which records jobs
 * and can be told to fail like an unreachable Redis.
 */
import {
  type ScanJobData,
  type ScanJobOptions,
  SCAN_JOB_NAME,
  scanJobOptions,
} from "@header-auditor/queue";

export interface ScanQueue {
  /** Hands the scan to the worker. Idempotent per scan id. */
  enqueue(scanId: string): Promise<void>;
}

/** Structural subset of BullMQ's `Queue` (so tests can't drift from `add`'s shape). */
export interface BullQueueLike {
  add(name: string, data: ScanJobData, options: ScanJobOptions): Promise<unknown>;
}

export function createBullScanQueue(queue: BullQueueLike): ScanQueue {
  return {
    async enqueue(scanId) {
      await queue.add(SCAN_JOB_NAME, { scanId }, scanJobOptions(scanId));
    },
  };
}

export class MemoryScanQueue implements ScanQueue {
  readonly jobs: string[] = [];
  /** Set to make the next `enqueue` calls reject, as if Redis were down. */
  failWith: Error | undefined;

  enqueue(scanId: string): Promise<void> {
    if (this.failWith !== undefined) return Promise.reject(this.failWith);
    if (!this.jobs.includes(scanId)) this.jobs.push(scanId);
    return Promise.resolve();
  }
}
