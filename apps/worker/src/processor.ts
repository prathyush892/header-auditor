/**
 * What happens to one job: claim the scan, run the engine, save the outcome.
 *
 * Two kinds of failure are kept apart on purpose:
 *
 * - The *target* failed (refused, timed out, blocked by the SSRF guard). That
 *   is a valid result: the scan is saved as FAILED with a fixed, user-safe
 *   reason and the job completes. Retrying would only hit the site again.
 * - The *infrastructure* failed (Postgres down, a bug). The error is thrown,
 *   BullMQ retries with backoff, and if every attempt fails the `failed`
 *   handler in worker.ts abandons the scan so the user sees a final state.
 */
import { parseScanJobData } from "@header-auditor/queue";

import {
  engineFindingRows,
  type EngineOptions,
  type EngineResult,
  runEngine,
  storedReport,
  TargetError,
} from "./engine.js";
import { type ClaimedScan, INTERNAL_FAILURE_MESSAGE, type WorkerScanStore } from "./store.js";

export interface ProcessorLogger {
  info(object: Record<string, unknown>, message: string): void;
  warn(object: Record<string, unknown>, message: string): void;
  error(object: Record<string, unknown>, message: string): void;
}

export type RunEngine = (target: string, options: EngineOptions) => Promise<EngineResult>;

export interface ProcessorDeps {
  readonly store: WorkerScanStore;
  readonly logger: ProcessorLogger;
  /** Engine options other than the per-site ones. */
  readonly engine: Omit<EngineOptions, "firstPartyHosts" | "signal">;
  readonly staleAfterMs: number;
  readonly now?: () => Date;
  /** Swapped in tests; defaults to the real engine. */
  readonly run?: RunEngine;
}

export type ProcessOutcome =
  | "succeeded"
  | "failed"
  /** Nothing to do: already finished, being run elsewhere, or the site was deleted. */
  | "skipped"
  /** The result could not be saved because another worker re-claimed the scan. */
  | "lease_lost";

export function createScanProcessor(deps: ProcessorDeps) {
  const now = deps.now ?? (() => new Date());
  const run = deps.run ?? runEngine;

  async function runClaimed(claim: ClaimedScan, signal?: AbortSignal): Promise<ProcessOutcome> {
    const { scanId } = claim;
    let result: EngineResult;
    try {
      result = await run(claim.requestedUrl, {
        ...deps.engine,
        firstPartyHosts: claim.firstPartyHosts,
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (error) {
      const target = error instanceof TargetError;
      // An engine bug is logged with its stack; the user only sees a fixed message.
      if (!target) deps.logger.error({ scanId, err: error }, "scan engine error");
      const saved = await deps.store.failScan(
        claim,
        target ? error.userMessage : INTERNAL_FAILURE_MESSAGE,
        now(),
      );
      if (!saved) return "lease_lost";
      deps.logger.info(
        { scanId, code: target ? error.code : "INTERNAL" },
        "scan finished: target failed",
      );
      return "failed";
    }

    const saved = await deps.store.completeScan(
      claim,
      {
        finalUrl: result.finalUrl,
        httpStatus: result.httpStatus,
        score: result.score,
        grade: result.grade,
        engineVersion: result.engine.version,
        report: storedReport(result),
        findings: engineFindingRows(result),
      },
      now(),
    );
    if (!saved) {
      deps.logger.warn({ scanId }, "scan lease lost before the result was saved");
      return "lease_lost";
    }
    deps.logger.info({ scanId, grade: result.grade, score: result.score }, "scan finished");
    return "succeeded";
  }

  return async function processScan(data: unknown, signal?: AbortSignal): Promise<ProcessOutcome> {
    // Throws on a malformed payload; BullMQ records it as a failed job.
    const { scanId } = parseScanJobData(data);
    const claimedAt = now();
    const claim = await deps.store.claimScan(
      scanId,
      claimedAt,
      new Date(claimedAt.getTime() - deps.staleAfterMs),
    );
    if (claim === null) {
      deps.logger.info({ scanId }, "scan not claimable, skipping");
      return "skipped";
    }
    deps.logger.info({ scanId, siteId: claim.siteId }, "scan started");
    try {
      return await runClaimed(claim, signal);
    } catch (error) {
      // Infrastructure failure while we held the scan. Hand it back (QUEUED)
      // so BullMQ's retry can claim it again instead of finding it RUNNING
      // and skipping it. Best effort: if the database is down this fails
      // too, and the stale-claim timeout or the final `failed` handler
      // takes over.
      try {
        await deps.store.releaseScan(claim);
      } catch (releaseError) {
        deps.logger.warn({ scanId, err: releaseError }, "could not release scan");
      }
      throw error;
    }
  };
}
