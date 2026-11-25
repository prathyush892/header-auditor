/**
 * The scan job: what goes on the queue and how BullMQ should treat it.
 *
 * The payload is only the scan id. Everything else (the URL, the owner's
 * first-party hosts) is read from the database by the worker. Redis is not a
 * trust boundary we want to depend on: anything that can write to it could
 * otherwise choose the URL the worker fetches. With an id-only payload, the
 * worst a forged job can do is ask for a scan that already exists.
 */

export const SCAN_QUEUE_NAME = "scans";
export const SCAN_JOB_NAME = "scan";
/** Redis key prefix; tests use a unique prefix per run so they never share keys. */
export const DEFAULT_QUEUE_PREFIX = "header-auditor";

/**
 * Attempts for infrastructure failures (database or Redis down, worker
 * crash). A target that times out or refuses the connection is a *result*
 * (a FAILED scan), not a retry: retrying would just hammer the target.
 */
export const SCAN_JOB_ATTEMPTS = 3;
/** First retry delay; BullMQ doubles it each attempt (5 s, 10 s). */
export const SCAN_JOB_BACKOFF_MS = 5_000;

export interface ScanJobData {
  readonly scanId: string;
}

export class ScanJobDataError extends Error {
  override readonly name = "ScanJobDataError";
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Validates a job payload read back from Redis. Exactly one key, `scanId`,
 * holding a lower-case UUID; anything else is rejected rather than ignored.
 */
export function parseScanJobData(data: unknown): ScanJobData {
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new ScanJobDataError("scan job data must be an object");
  }
  const keys = Object.keys(data);
  if (keys.length !== 1 || keys[0] !== "scanId") {
    throw new ScanJobDataError("scan job data must have exactly one key: scanId");
  }
  const { scanId } = data as { scanId: unknown };
  if (typeof scanId !== "string" || !UUID.test(scanId)) {
    throw new ScanJobDataError("scanId must be a lower-case UUID");
  }
  return { scanId };
}

/** Structural subset of BullMQ's `JobsOptions` that we set. */
export interface ScanJobOptions {
  readonly jobId: string;
  readonly attempts: number;
  readonly backoff: { readonly type: "exponential"; readonly delay: number };
  readonly removeOnComplete: { readonly age: number; readonly count: number };
  readonly removeOnFail: { readonly age: number; readonly count: number };
}

const DAY_SECONDS = 86_400;

/**
 * Options for enqueuing `scanId`. The job id *is* the scan id, so enqueuing
 * the same scan twice (a retried HTTP request, a replayed outbox row) is a
 * no-op in BullMQ rather than a second scan of the target.
 *
 * Results live in Postgres, so finished jobs are trimmed from Redis: a day of
 * completed jobs (for debugging) and a week of failed ones.
 */
export function scanJobOptions(scanId: string): ScanJobOptions {
  parseScanJobData({ scanId });
  return {
    jobId: scanId,
    attempts: SCAN_JOB_ATTEMPTS,
    backoff: { type: "exponential", delay: SCAN_JOB_BACKOFF_MS },
    removeOnComplete: { age: DAY_SECONDS, count: 1_000 },
    removeOnFail: { age: 7 * DAY_SECONDS, count: 5_000 },
  };
}

/** Prefix for Redis keys: letters, digits, `-`, `_`, `.`, up to 64 characters. */
export function isQueuePrefix(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value);
}
