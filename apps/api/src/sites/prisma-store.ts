/**
 * `SiteStore` backed by PostgreSQL through Prisma (`@header-auditor/db`).
 *
 * Like the auth store, the client is typed structurally so the API build has
 * no dependency on the generated client; tests pass the real one.
 *
 * Every `where` includes `ownerId`. Updates and deletes use a single
 * statement keyed on `(id, ownerId)`, so there is no read-then-write window in
 * which a site could change hands or a check could be skipped.
 */
import { isUniqueViolation } from "../auth/prisma-store.js";
import { isActiveSchedule } from "../schedules/cadence.js";
import {
  type ListSitesOptions,
  type NewSite,
  type Schedule,
  SiteExistsError,
  SiteLimitError,
  type SitePatch,
  type SiteRecord,
  type SiteStore,
} from "./store.js";

interface SiteRow {
  readonly id: string;
  readonly ownerId: string;
  readonly name: string;
  readonly url: string;
  readonly verificationToken: string;
  readonly verifiedAt: Date | null;
  readonly schedule: Schedule;
  readonly nextScanAt: Date | null;
  readonly firstPartyHosts: string[];
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

interface SiteSelect {
  id: true;
  ownerId: true;
  name: true;
  url: true;
  verificationToken: true;
  verifiedAt: true;
  schedule: true;
  nextScanAt: true;
  firstPartyHosts: true;
  createdAt: true;
  updatedAt: true;
}

const SITE_SELECT: SiteSelect = {
  id: true,
  ownerId: true,
  name: true,
  url: true,
  verificationToken: true,
  verifiedAt: true,
  schedule: true,
  nextScanAt: true,
  firstPartyHosts: true,
  createdAt: true,
  updatedAt: true,
};

type Order = "desc";

interface SiteListWhere {
  ownerId: string;
  OR?: [{ createdAt: { lt: Date } }, { createdAt: Date; id: { lt: string } }];
}

interface SiteData {
  name?: string;
  firstPartyHosts?: string[];
}

/** The subset of the site delegate both the client and a transaction expose. */
interface SiteDelegate {
  findMany(args: {
    where: SiteListWhere;
    orderBy: [{ createdAt: Order }, { id: Order }];
    take: number;
    select: SiteSelect;
  }): PromiseLike<SiteRow[]>;
  findFirst(args: {
    where: { id: string; ownerId: string } | { ownerId: string; url: string };
    select: SiteSelect;
  }): PromiseLike<SiteRow | null>;
  count(args: { where: { ownerId: string } }): PromiseLike<number>;
  create(args: {
    data: {
      ownerId: string;
      name: string;
      url: string;
      verificationToken: string;
      schedule: Schedule;
      nextScanAt: Date | null;
      firstPartyHosts: string[];
    };
    select: SiteSelect;
  }): PromiseLike<SiteRow>;
  /** Only used to change the schedule, and only when it actually changes. */
  updateMany(args: {
    where: { id: string; ownerId: string; schedule: { not: Schedule } };
    data: { schedule: Schedule; nextScanAt: Date | null };
  }): PromiseLike<{ count: number }>;
  update(args: {
    where: { id: string; ownerId: string };
    data: SiteData;
    select: SiteSelect;
  }): PromiseLike<SiteRow>;
  deleteMany(args: { where: { id: string; ownerId: string } }): PromiseLike<{ count: number }>;
}

export interface PrismaSiteTransaction {
  readonly site: SiteDelegate;
  $queryRaw(query: TemplateStringsArray, ...values: unknown[]): PromiseLike<unknown>;
}

export interface PrismaSiteClient {
  readonly site: SiteDelegate;
  /** createSite: quota check + insert. updateSite: schedule change + other fields. */
  $transaction<R>(fn: (tx: PrismaSiteTransaction) => Promise<R>): Promise<R>;
}

/** Prisma's "record to update not found" (duck-typed, like `isUniqueViolation`). */
export function isRecordNotFound(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "P2025";
}

function toRecord(row: SiteRow): SiteRecord {
  return { ...row, firstPartyHosts: [...row.firstPartyHosts] };
}

function listWhere(ownerId: string, options: ListSitesOptions): SiteListWhere {
  const { after } = options;
  if (after === undefined) return { ownerId };
  // Keyset pagination on (created_at DESC, id DESC): rows strictly after the cursor.
  return {
    ownerId,
    OR: [
      { createdAt: { lt: after.createdAt } },
      { createdAt: after.createdAt, id: { lt: after.id } },
    ],
  };
}

function patchData(patch: SitePatch): SiteData {
  return {
    ...(patch.name === undefined ? {} : { name: patch.name }),
    ...(patch.firstPartyHosts === undefined ? {} : { firstPartyHosts: [...patch.firstPartyHosts] }),
  };
}

export function createPrismaSiteStore(
  client: PrismaSiteClient,
  now: () => Date = () => new Date(),
): SiteStore {
  return {
    async listSites(ownerId, options) {
      const rows = await client.site.findMany({
        where: listWhere(ownerId, options),
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        take: options.limit,
        select: SITE_SELECT,
      });
      return rows.map(toRecord);
    },

    async findSite(ownerId, id) {
      const row = await client.site.findFirst({ where: { id, ownerId }, select: SITE_SELECT });
      return row === null ? null : toRecord(row);
    },

    async createSite(site: NewSite, maxSites: number) {
      try {
        return await client.$transaction(async (tx) => {
          // Lock the owner's row: concurrent creates for one user queue up here,
          // so "count, then insert" can't let two requests both squeeze under the quota.
          await tx.$queryRaw`SELECT 1 FROM "users" WHERE "id" = ${site.ownerId}::uuid FOR UPDATE`;
          const existing = await tx.site.findFirst({
            where: { ownerId: site.ownerId, url: site.url },
            select: SITE_SELECT,
          });
          if (existing !== null) throw new SiteExistsError();
          const count = await tx.site.count({ where: { ownerId: site.ownerId } });
          if (count >= maxSites) throw new SiteLimitError(maxSites);
          const row = await tx.site.create({
            data: {
              ...site,
              firstPartyHosts: [...site.firstPartyHosts],
              nextScanAt: isActiveSchedule(site.schedule) ? now() : null,
            },
            select: SITE_SELECT,
          });
          return toRecord(row);
        });
      } catch (error) {
        // Backstop: the unique index (owner_id, url) has the final word.
        if (isUniqueViolation(error)) throw new SiteExistsError();
        throw error;
      }
    },

    async updateSite(ownerId, id, patch) {
      const { schedule } = patch;
      try {
        return await client.$transaction(async (tx) => {
          if (schedule !== undefined) {
            // Conditional on the schedule actually changing, decided by the
            // database: re-saving the same schedule keeps next_scan_at, and
            // there is no read-then-write window for the scheduler to race.
            // (Same rule as nextScanAtForChange.)
            await tx.site.updateMany({
              where: { id, ownerId, schedule: { not: schedule } },
              data: { schedule, nextScanAt: isActiveSchedule(schedule) ? now() : null },
            });
          }
          const row = await tx.site.update({
            where: { id, ownerId },
            data: patchData(patch),
            select: SITE_SELECT,
          });
          return toRecord(row);
        });
      } catch (error) {
        if (isRecordNotFound(error)) return null;
        throw error;
      }
    },

    async deleteSite(ownerId, id) {
      const { count } = await client.site.deleteMany({ where: { id, ownerId } });
      return count > 0;
    },
  };
}
