/**
 * The scan scheduler: every tick, queue a SCHEDULED scan for each site whose
 * `next_scan_at` has passed, and move `next_scan_at` one interval forward.
 *
 * Safe to run as several processes (a rolling deploy briefly has two):
 *
 * 1. Claim first. `moveNextScan` is a compare-and-set on the run's due time,
 *    so for each run exactly one process wins and the others skip it.
 * 2. Then create the scan through `ScanStore.createScan`, the same path as a
 *    manual scan, so the per-site and per-user limits apply unchanged.
 * 3. Then enqueue the scan id (the job never carries a URL; see step 15).
 *
 * A crash between 1 and 2 loses that one run (at-most-once per period); the
 * next period comes round as normal. That's the right trade for a monitor:
 * a skipped daily scan is harmless, a duplicate burst against someone's site
 * is not.
 */
import type { ScanQueue } from "../scans/queue.js";
import { type CreateScanLimits, ENQUEUE_FAILED_MESSAGE, type ScanStore } from "../scans/store.js";
import { nextRunAfter } from "./cadence.js";
import type { DueSite, ScheduleStore } from "./store.js";

/** The pino methods the scheduler uses (a fastify or worker logger fits). */
export interface SchedulerLogger {
  info(obj: object, msg: string): void;
  warn(obj: object, msg: string): void;
  error(obj: object, msg: string): void;
}

export interface SchedulerOptions {
  readonly schedules: ScheduleStore;
  readonly scans: ScanStore;
  readonly queue: ScanQueue;
  readonly limits: CreateScanLimits;
  readonly logger: SchedulerLogger;
  /** Sites read per query. */
  readonly batchSize: number;
  /** Upper bound on queries per tick, so one tick always ends. */
  readonly maxBatchesPerTick: number;
  /** How soon to try again when a run couldn't be queued (limit hit, Redis down). */
  readonly retryDelayMs: number;
  /** Time between the end of one tick and the start of the next. */
  readonly intervalMs: number;
  readonly now?: () => Date;
}

export type RunOutcome =
  /** A SCHEDULED scan was created and handed to the queue. */
  | "queued"
  /** A scan of the site was already queued or running; it counts for this run. */
  | "alreadyRunning"
  /** The owner is at their active-scan limit; retried after `retryDelayMs`. */
  | "deferred"
  /** Another scheduler process claimed this run first. */
  | "claimedElsewhere"
  /** The site disappeared between the query and the claim. */
  | "removed"
  /** Database or queue error; retried after `retryDelayMs`. */
  | "failed";

export type TickSummary = Readonly<Record<RunOutcome, number>> & { readonly due: number };

export interface Scheduler {
  /** One pass over everything due now. Never throws for a single site's failure. */
  tick(): Promise<TickSummary>;
  /** Runs a tick now and then every `intervalMs` until `stop()`. */
  start(): void;
  /** Cancels the next tick and waits for a running one to finish. Idempotent. */
  stop(): Promise<void>;
}

function emptySummary(): Record<RunOutcome | "due", number> {
  return {
    due: 0,
    queued: 0,
    alreadyRunning: 0,
    deferred: 0,
    claimedElsewhere: 0,
    removed: 0,
    failed: 0,
  };
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : typeof error;
}

export function validateSchedulerOptions(options: SchedulerOptions): void {
  const positive: [string, number][] = [
    ["batchSize", options.batchSize],
    ["maxBatchesPerTick", options.maxBatchesPerTick],
    ["retryDelayMs", options.retryDelayMs],
    ["intervalMs", options.intervalMs],
  ];
  for (const [name, value] of positive) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new RangeError(`scheduler: ${name} must be a positive integer`);
    }
  }
}

export function createScheduler(options: SchedulerOptions): Scheduler {
  validateSchedulerOptions(options);
  const { schedules, scans, queue, limits, logger } = options;
  const now = options.now ?? (() => new Date());

  /** Pushes a claimed run to `retryAt`, but never later than the next regular run. */
  async function retryLater(site: DueSite, claimed: Date, at: Date): Promise<void> {
    const retryAt = new Date(Math.min(claimed.getTime(), at.getTime() + options.retryDelayMs));
    try {
      await schedules.moveNextScan(site.id, claimed, retryAt);
    } catch (error) {
      // The run stays claimed and simply happens at the next regular time.
      logger.error({ siteId: site.id, err: errorName(error) }, "could not reschedule retry");
    }
  }

  async function runOne(site: DueSite, at: Date): Promise<RunOutcome> {
    const claimed = nextRunAfter(site.nextScanAt, site.schedule, at);
    if (!(await schedules.moveNextScan(site.id, site.nextScanAt, claimed))) {
      return "claimedElsewhere";
    }
    try {
      const result = await scans.createScan(site.ownerId, site.id, "SCHEDULED", limits);
      switch (result.kind) {
        case "site_not_found":
          return "removed";
        case "in_progress":
          return "alreadyRunning";
        case "limit_reached":
          await retryLater(site, claimed, at);
          return "deferred";
        case "created":
          break;
      }
      try {
        await queue.enqueue(result.scan.id);
      } catch (error) {
        // Same as the POST route: don't leave a QUEUED row no worker will see.
        await scans.failQueuedScan(result.scan.id, ENQUEUE_FAILED_MESSAGE, at);
        throw error;
      }
      return "queued";
    } catch (error) {
      logger.error({ siteId: site.id, err: errorName(error) }, "scheduled scan failed");
      await retryLater(site, claimed, at);
      return "failed";
    }
  }

  async function tick(): Promise<TickSummary> {
    const at = now();
    const summary = emptySummary();
    for (let batch = 0; batch < options.maxBatchesPerTick; batch += 1) {
      const due = await schedules.findDueSites(at, options.batchSize);
      summary.due += due.length;
      // One site at a time: createScan locks the owner's row anyway, and a
      // steady trickle is kinder to the queue than a burst.
      for (const site of due) {
        let outcome: RunOutcome;
        try {
          outcome = await runOne(site, at);
        } catch (error) {
          // The claim itself failed (database unreachable): nothing changed.
          logger.error({ siteId: site.id, err: errorName(error) }, "could not claim scheduled run");
          outcome = "failed";
        }
        // eslint-disable-next-line security/detect-object-injection -- `outcome` is a closed union
        summary[outcome] += 1;
      }
      // Claimed sites are no longer due, so the next query returns new ones.
      if (due.length < options.batchSize) break;
    }
    if (summary.due > 0) logger.info({ ...summary }, "scheduler tick");
    return summary;
  }

  let timer: NodeJS.Timeout | undefined;
  let running: Promise<unknown> | undefined;
  let stopped = false;

  function loop(): void {
    running = tick()
      .catch((error: unknown) => {
        // e.g. the due-sites query failed: log it and try again next tick.
        logger.error({ err: errorName(error) }, "scheduler tick failed");
      })
      .finally(() => {
        running = undefined;
        if (!stopped) timer = setTimeout(loop, options.intervalMs);
      });
  }

  return {
    tick,
    start() {
      if (stopped) throw new Error("scheduler: cannot restart a stopped scheduler");
      if (timer !== undefined || running !== undefined) return;
      loop();
    },
    async stop() {
      stopped = true;
      clearTimeout(timer);
      timer = undefined;
      await running;
    },
  };
}
