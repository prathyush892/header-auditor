/**
 * What the scheduler needs from the database: which sites are due, and an
 * atomic way to claim one run.
 *
 * This is the one place that reads sites without an owner filter, because the
 * scheduler works for every user. It never returns anything to a client, and
 * it hands each site's owner id to `ScanStore.createScan`, which applies the
 * same ownership and limit checks as a click on "Scan now".
 */
import type { ActiveSchedule } from "./cadence.js";
import type { MemorySiteStore } from "../sites/store.js";

export interface DueSite {
  readonly id: string;
  readonly ownerId: string;
  readonly schedule: ActiveSchedule;
  /** The run being claimed; also the expected value for `moveNextScan`. */
  readonly nextScanAt: Date;
}

export interface ScheduleStore {
  /**
   * Verified sites with a schedule whose next run is at or before `now`,
   * longest-overdue first (ties by id), at most `limit` of them.
   */
  findDueSites(now: Date, limit: number): Promise<DueSite[]>;
  /**
   * Compare-and-set: moves `next_scan_at` from `expected` to `next`. Returns
   * false if it had already moved (another scheduler claimed this run, or the
   * owner changed or removed the schedule), and then the caller must skip it.
   */
  moveNextScan(siteId: string, expected: Date, next: Date): Promise<boolean>;
}

/** Scheduler view of a `MemorySiteStore`, for tests. Same rules as the SQL. */
export class MemoryScheduleStore implements ScheduleStore {
  constructor(private readonly sites: MemorySiteStore) {}

  findDueSites(now: Date, limit: number): Promise<DueSite[]> {
    const due: DueSite[] = [];
    for (const site of this.sites.all()) {
      if (
        site.schedule !== "NONE" &&
        site.verifiedAt !== null &&
        site.nextScanAt !== null &&
        site.nextScanAt.getTime() <= now.getTime()
      ) {
        due.push({
          id: site.id,
          ownerId: site.ownerId,
          schedule: site.schedule,
          nextScanAt: site.nextScanAt,
        });
      }
    }
    due.sort(
      (a, b) =>
        a.nextScanAt.getTime() - b.nextScanAt.getTime() || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
    );
    return Promise.resolve(due.slice(0, limit));
  }

  moveNextScan(siteId: string, expected: Date, next: Date): Promise<boolean> {
    // No await between the read and the write: atomic, like the conditional UPDATE.
    const site = this.sites.all().find((s) => s.id === siteId);
    if (
      site === undefined ||
      site.schedule === "NONE" ||
      site.nextScanAt?.getTime() !== expected.getTime()
    ) {
      return Promise.resolve(false);
    }
    this.sites.patchRecord(siteId, { nextScanAt: next });
    return Promise.resolve(true);
  }
}
