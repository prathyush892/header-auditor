/**
 * Persistence boundary for scans, as the API sees them.
 *
 * Like `SiteStore`, every method is scoped by the owner: a scan is reached
 * through its site, and the site through the signed-in user. The worker has
 * its own store (claim, complete, fail) in apps/worker; the API never writes
 * results and the worker never decides who may see them.
 */
import { randomUUID } from "node:crypto";

import type { SiteStore } from "../sites/store.js";

export const SCAN_STATUSES = ["QUEUED", "RUNNING", "SUCCEEDED", "FAILED"] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];
export const ACTIVE_STATUSES: readonly ScanStatus[] = ["QUEUED", "RUNNING"];

export type ScanTrigger = "MANUAL" | "SCHEDULED";
export type ScanGrade = "A" | "B" | "C" | "D" | "F";
export type FindingCategory = "HEADERS" | "TLS" | "CONTENT" | "DNS" | "WELL_KNOWN";
export type FindingStatus = "PASS" | "WARN" | "FAIL" | "INFO";

export interface ScanRecord {
  readonly id: string;
  readonly siteId: string;
  readonly status: ScanStatus;
  readonly trigger: ScanTrigger;
  readonly requestedUrl: string;
  readonly finalUrl: string | null;
  readonly httpStatus: number | null;
  readonly score: number | null;
  readonly grade: ScanGrade | null;
  readonly engineVersion: string | null;
  readonly error: string | null;
  readonly createdAt: Date;
  readonly startedAt: Date | null;
  readonly finishedAt: Date | null;
}

export interface FindingRecord {
  readonly category: FindingCategory;
  readonly check: string;
  readonly status: FindingStatus;
  readonly detail: string;
  readonly weight: number;
  readonly score: number;
  readonly recommendation: string;
  readonly position: number;
}

export interface ScanDetail extends ScanRecord {
  /** Full engine output (null until the scan succeeds). */
  readonly report: unknown;
  /** Ordered by `position`, as the engine listed them. */
  readonly findings: readonly FindingRecord[];
}

export interface CreateScanLimits {
  /** Queued + running scans one user may have across all their sites. */
  readonly maxActivePerUser: number;
  /**
   * A queued/running scan older than this no longer blocks new scans. A worker
   * that died mid-scan must not lock a site out forever.
   */
  readonly activeWindowMs: number;
}

export type CreateScanResult =
  | { readonly kind: "created"; readonly scan: ScanRecord }
  /** The site doesn't exist or belongs to someone else (indistinguishable on purpose). */
  | { readonly kind: "site_not_found" }
  /** This site already has a scan waiting or running. */
  | { readonly kind: "in_progress"; readonly scan: ScanRecord }
  /** The user is at `maxActivePerUser`. */
  | { readonly kind: "limit_reached"; readonly limit: number };

export interface ScanStore {
  /**
   * Atomically: confirms the owner owns the site, checks the per-site and
   * per-user active-scan limits, and inserts a QUEUED scan for the site's URL.
   */
  createScan(
    ownerId: string,
    siteId: string,
    trigger: ScanTrigger,
    limits: CreateScanLimits,
  ): Promise<CreateScanResult>;
  /** Null when the scan, the site, or the ownership doesn't match. */
  findScan(ownerId: string, siteId: string, scanId: string): Promise<ScanDetail | null>;
  /**
   * Marks a QUEUED scan FAILED when it could not be handed to the queue.
   * No-op if the scan has moved on (a worker already picked it up).
   */
  failQueuedScan(scanId: string, error: string, at: Date): Promise<void>;
}

/** Stored on a queued/running scan that outlived the active window (its worker died). */
export const STALE_SCAN_MESSAGE = "The scan did not finish in time and was abandoned.";

/** User-safe reason stored when Redis refused the job. */
export const ENQUEUE_FAILED_MESSAGE = "The scan could not be queued. Please try again.";

function isActive(scan: ScanRecord, now: Date, windowMs: number): boolean {
  return (
    ACTIVE_STATUSES.includes(scan.status) && now.getTime() - scan.createdAt.getTime() < windowMs
  );
}

/**
 * In-process store for tests, sharing ownership data with a `SiteStore`.
 * `complete()` stands in for the worker so route tests can read results.
 */
export class MemoryScanStore implements ScanStore {
  private readonly scans = new Map<string, ScanDetail>();
  /** Owner of each scan's site, recorded at creation (a site never changes owner). */
  private readonly owners = new Map<string, string>();

  constructor(
    private readonly sites: SiteStore,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async createScan(
    ownerId: string,
    siteId: string,
    trigger: ScanTrigger,
    limits: CreateScanLimits,
  ): Promise<CreateScanResult> {
    const site = await this.sites.findSite(ownerId, siteId);
    if (site === null) return { kind: "site_not_found" };
    // No await from here to the insert, so the checks and the write are atomic.
    const now = this.now();
    for (const scan of this.scans.values()) {
      if (
        scan.siteId === siteId &&
        ACTIVE_STATUSES.includes(scan.status) &&
        !isActive(scan, now, limits.activeWindowMs)
      ) {
        this.scans.set(scan.id, {
          ...scan,
          status: "FAILED",
          error: STALE_SCAN_MESSAGE,
          finishedAt: now,
        });
      }
    }
    const active = [...this.scans.values()].filter((scan) =>
      isActive(scan, now, limits.activeWindowMs),
    );
    const sameSite = active.find((scan) => scan.siteId === siteId);
    if (sameSite !== undefined) return { kind: "in_progress", scan: sameSite };
    const mine = active.filter((scan) => this.owners.get(scan.id) === ownerId);
    if (mine.length >= limits.maxActivePerUser) {
      return { kind: "limit_reached", limit: limits.maxActivePerUser };
    }
    const scan: ScanDetail = {
      id: randomUUID(),
      siteId,
      status: "QUEUED",
      trigger,
      requestedUrl: site.url,
      finalUrl: null,
      httpStatus: null,
      score: null,
      grade: null,
      engineVersion: null,
      error: null,
      createdAt: now,
      startedAt: null,
      finishedAt: null,
      report: null,
      findings: [],
    };
    this.scans.set(scan.id, scan);
    this.owners.set(scan.id, ownerId);
    return { kind: "created", scan };
  }

  async findScan(ownerId: string, siteId: string, scanId: string): Promise<ScanDetail | null> {
    const scan = this.scans.get(scanId);
    if (scan?.siteId !== siteId) return null;
    // Ask the site store, so a deleted site hides its scans like the SQL cascade does.
    const site = await this.sites.findSite(ownerId, siteId);
    return site === null ? null : scan;
  }

  failQueuedScan(scanId: string, error: string, at: Date): Promise<void> {
    const scan = this.scans.get(scanId);
    if (scan?.status === "QUEUED") {
      this.scans.set(scanId, { ...scan, status: "FAILED", error, finishedAt: at });
    }
    return Promise.resolve();
  }

  /** Test helper: what the worker does when a scan finishes. */
  complete(scanId: string, patch: Partial<Omit<ScanDetail, "id" | "siteId">>): void {
    const scan = this.scans.get(scanId);
    if (scan !== undefined) this.scans.set(scanId, { ...scan, ...patch });
  }

  /** Test helper: every scan, in insertion order. */
  all(): ScanDetail[] {
    return [...this.scans.values()];
  }
}
