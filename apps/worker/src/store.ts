/**
 * The worker's view of the scans table: claim a scan, then write its result.
 *
 * Claiming is a conditional UPDATE (QUEUED -> RUNNING), so if BullMQ ever
 * delivers a job twice (a stalled job is redelivered while the first worker is
 * in fact still alive) only one worker gets the row. The `startedAt` it wrote
 * is its lease: results are only saved `WHERE status = 'RUNNING' AND
 * started_at = <lease>`, so a worker whose scan was re-claimed after it went
 * stale can't overwrite the newer run. This is a fencing token, the same idea
 * as an optimistic-locking version column.
 */
import type { FindingRow } from "@header-auditor/db";

export interface ScanLease {
  readonly scanId: string;
  /** Written at claim time; doubles as the fencing token. */
  readonly startedAt: Date;
}

export interface ClaimedScan extends ScanLease {
  readonly siteId: string;
  readonly requestedUrl: string;
  readonly firstPartyHosts: readonly string[];
}

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface ScanSuccess {
  readonly finalUrl: string;
  readonly httpStatus: number;
  readonly score: number;
  readonly grade: Grade;
  readonly engineVersion: string;
  readonly report: unknown;
  readonly findings: readonly FindingRow[];
}

export interface WorkerScanStore {
  /**
   * QUEUED -> RUNNING, or re-claims a RUNNING scan whose `startedAt` is older
   * than `staleBefore` (its worker died). Null when there is nothing to do:
   * the scan finished, was abandoned, is being run by a live worker, or its
   * site was deleted.
   */
  claimScan(scanId: string, now: Date, staleBefore: Date): Promise<ClaimedScan | null>;
  /** RUNNING -> SUCCEEDED with findings, in one transaction. False if the lease was lost. */
  completeScan(lease: ScanLease, result: ScanSuccess, finishedAt: Date): Promise<boolean>;
  /** RUNNING -> FAILED with a user-safe reason. False if the lease was lost. */
  failScan(lease: ScanLease, error: string, finishedAt: Date): Promise<boolean>;
  /** RUNNING -> QUEUED, so a retry can claim it again. False if the lease was lost. */
  releaseScan(lease: ScanLease): Promise<boolean>;
  /**
   * QUEUED/RUNNING -> FAILED without a lease, for a job that ran out of
   * retries (the worker crashed or the database kept failing).
   */
  abandonScan(scanId: string, error: string, finishedAt: Date): Promise<boolean>;
}

/** Stored when a job exhausted its retries. */
export const ABANDONED_MESSAGE = "The scan could not be completed. Please try again later.";
/** Stored when the engine itself threw (a bug, not the target). */
export const INTERNAL_FAILURE_MESSAGE = "The scan failed because of an internal error.";

type Status = "QUEUED" | "RUNNING" | "SUCCEEDED" | "FAILED";

interface MemoryScan {
  id: string;
  siteId: string;
  status: Status;
  requestedUrl: string;
  firstPartyHosts: readonly string[];
  startedAt: Date | null;
  finishedAt: Date | null;
  error: string | null;
  result: ScanSuccess | null;
}

/** In-process store for processor tests. */
export class MemoryWorkerScanStore implements WorkerScanStore {
  readonly scans = new Map<string, MemoryScan>();

  /** Test helper: a QUEUED scan, as the API would have inserted it. */
  add(scan: Pick<MemoryScan, "id" | "requestedUrl"> & Partial<MemoryScan>): MemoryScan {
    const row: MemoryScan = {
      siteId: "00000000-0000-4000-8000-000000000001",
      status: "QUEUED",
      firstPartyHosts: [],
      startedAt: null,
      finishedAt: null,
      error: null,
      result: null,
      ...scan,
    };
    this.scans.set(row.id, row);
    return row;
  }

  claimScan(scanId: string, now: Date, staleBefore: Date): Promise<ClaimedScan | null> {
    const scan = this.scans.get(scanId);
    const claimable =
      scan !== undefined &&
      (scan.status === "QUEUED" ||
        (scan.status === "RUNNING" &&
          scan.startedAt !== null &&
          scan.startedAt.getTime() < staleBefore.getTime()));
    if (!claimable) return Promise.resolve(null);
    scan.status = "RUNNING";
    scan.startedAt = now;
    return Promise.resolve({
      scanId,
      startedAt: now,
      siteId: scan.siteId,
      requestedUrl: scan.requestedUrl,
      firstPartyHosts: [...scan.firstPartyHosts],
    });
  }

  completeScan(lease: ScanLease, result: ScanSuccess, finishedAt: Date): Promise<boolean> {
    const scan = this.leased(lease);
    if (scan === undefined) return Promise.resolve(false);
    Object.assign(scan, { status: "SUCCEEDED", result, finishedAt, error: null });
    return Promise.resolve(true);
  }

  failScan(lease: ScanLease, error: string, finishedAt: Date): Promise<boolean> {
    const scan = this.leased(lease);
    if (scan === undefined) return Promise.resolve(false);
    Object.assign(scan, { status: "FAILED", error, finishedAt });
    return Promise.resolve(true);
  }

  releaseScan(lease: ScanLease): Promise<boolean> {
    const scan = this.leased(lease);
    if (scan === undefined) return Promise.resolve(false);
    Object.assign(scan, { status: "QUEUED", startedAt: null });
    return Promise.resolve(true);
  }

  abandonScan(scanId: string, error: string, finishedAt: Date): Promise<boolean> {
    const scan = this.scans.get(scanId);
    if (scan === undefined || (scan.status !== "QUEUED" && scan.status !== "RUNNING")) {
      return Promise.resolve(false);
    }
    Object.assign(scan, { status: "FAILED", error, finishedAt });
    return Promise.resolve(true);
  }

  private leased(lease: ScanLease): MemoryScan | undefined {
    const scan = this.scans.get(lease.scanId);
    return scan?.status === "RUNNING" && scan.startedAt?.getTime() === lease.startedAt.getTime()
      ? scan
      : undefined;
  }
}
