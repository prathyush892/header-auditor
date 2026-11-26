/**
 * `ScheduleStore` on PostgreSQL, typed structurally like the other stores.
 *
 * `findDueSites` is a range scan on `sites_next_scan_at_idx`. `moveNextScan`
 * is a single conditional UPDATE, so of any number of scheduler processes
 * that read the same due site, exactly one sees "1 row updated".
 */
import type { ActiveSchedule } from "./cadence.js";
import type { DueSite, ScheduleStore } from "./store.js";

interface DueRow {
  readonly id: string;
  readonly ownerId: string;
  readonly schedule: "NONE" | ActiveSchedule;
  readonly nextScanAt: Date | null;
}

export interface PrismaScheduleClient {
  readonly site: {
    findMany(args: {
      where: {
        schedule: { not: "NONE" };
        verifiedAt: { not: null };
        nextScanAt: { lte: Date };
      };
      orderBy: [{ nextScanAt: "asc" }, { id: "asc" }];
      take: number;
      select: { id: true; ownerId: true; schedule: true; nextScanAt: true };
    }): PromiseLike<DueRow[]>;
  };
  $executeRaw(query: TemplateStringsArray, ...values: unknown[]): PromiseLike<number>;
}

function toDueSite(row: DueRow): DueSite | null {
  // The WHERE clause and the CHECK constraint rule these out; the guard keeps
  // the types honest without a cast.
  if (row.schedule === "NONE" || row.nextScanAt === null) return null;
  return { id: row.id, ownerId: row.ownerId, schedule: row.schedule, nextScanAt: row.nextScanAt };
}

export function createPrismaScheduleStore(client: PrismaScheduleClient): ScheduleStore {
  return {
    async findDueSites(now, limit) {
      const rows = await client.site.findMany({
        where: { schedule: { not: "NONE" }, verifiedAt: { not: null }, nextScanAt: { lte: now } },
        orderBy: [{ nextScanAt: "asc" }, { id: "asc" }],
        take: limit,
        select: { id: true, ownerId: true, schedule: true, nextScanAt: true },
      });
      return rows.map(toDueSite).filter((site): site is DueSite => site !== null);
    },

    async moveNextScan(siteId, expected, next) {
      // Raw SQL on purpose: Prisma's update would also bump updated_at, which
      // records owner edits, not scheduler bookkeeping.
      const count = await client.$executeRaw`
        UPDATE "sites" SET "next_scan_at" = ${next}
        WHERE "id" = ${siteId}::uuid
          AND "next_scan_at" = ${expected}
          AND "schedule" <> 'NONE'`;
      return count === 1;
    },
  };
}
