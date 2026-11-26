/**
 * `ScanStore` backed by PostgreSQL through Prisma, typed structurally like the
 * auth and site stores (tests pass the real generated client).
 *
 * Ownership is enforced in SQL, not in JavaScript: reads filter on
 * `site: { ownerId }`, which Prisma turns into a join on `sites.owner_id`.
 */
import { isUniqueViolation } from "../auth/prisma-store.js";
import {
  ACTIVE_STATUSES,
  type CreateScanLimits,
  type FindingRecord,
  type ScanDetail,
  type ScanCursor,
  type ScanRecord,
  type ScanStatus,
  type ScanStore,
  type ScanTrigger,
  STALE_SCAN_MESSAGE,
} from "./store.js";

type ScanRow = ScanRecord;

interface ScanSelect {
  id: true;
  siteId: true;
  status: true;
  trigger: true;
  requestedUrl: true;
  finalUrl: true;
  httpStatus: true;
  score: true;
  grade: true;
  engineVersion: true;
  error: true;
  createdAt: true;
  startedAt: true;
  finishedAt: true;
}

const SCAN_SELECT: ScanSelect = {
  id: true,
  siteId: true,
  status: true,
  trigger: true,
  requestedUrl: true,
  finalUrl: true,
  httpStatus: true,
  score: true,
  grade: true,
  engineVersion: true,
  error: true,
  createdAt: true,
  startedAt: true,
  finishedAt: true,
};

interface FindingSelect {
  category: true;
  check: true;
  status: true;
  detail: true;
  weight: true;
  score: true;
  recommendation: true;
  position: true;
}

const FINDING_SELECT: FindingSelect = {
  category: true,
  check: true,
  status: true,
  detail: true,
  weight: true,
  score: true,
  recommendation: true,
  position: true,
};

type DetailSelect = ScanSelect & {
  report: true;
  findings: { select: FindingSelect; orderBy: { position: "asc" } };
};

type DetailRow = ScanRow & { report: unknown; findings: FindingRecord[] };

interface ActiveWhere {
  status: { in: ScanStatus[] };
  createdAt: { gt: Date };
}

interface HistoryWhere {
  siteId: string;
  site: { ownerId: string };
  OR?: [{ createdAt: { lt: Date } }, { createdAt: Date; id: { lt: string } }];
}

interface ScanDelegate {
  /** The active-scan check (`take: 1`) and the history page. */
  findMany(args: {
    where: (ActiveWhere & { siteId: string }) | HistoryWhere;
    orderBy?: [{ createdAt: "desc" }, { id: "desc" }];
    take: number;
    select: ScanSelect;
  }): PromiseLike<ScanRow[]>;
  findFirst(args: {
    where: { id: string; siteId: string; site: { ownerId: string } };
    select: DetailSelect;
  }): PromiseLike<DetailRow | null>;
  count(args: { where: ActiveWhere & { site: { ownerId: string } } }): PromiseLike<number>;
  create(args: {
    data: {
      siteId: string;
      trigger: ScanTrigger;
      requestedUrl: string;
      status: "QUEUED";
      createdAt: Date;
    };
    select: ScanSelect;
  }): PromiseLike<ScanRow>;
  updateMany(args: {
    where:
      | { id: string; status: "QUEUED" }
      | { siteId: string; status: { in: ScanStatus[] }; createdAt: { lte: Date } };
    data: { status: "FAILED"; error: string; finishedAt: Date };
  }): PromiseLike<{ count: number }>;
}

interface SiteLookup {
  findFirst(args: {
    where: { id: string; ownerId: string };
    select: { id: true; url: true };
  }): PromiseLike<{ id: string; url: string } | null>;
}

export interface PrismaScanTransaction {
  readonly scan: ScanDelegate;
  readonly site: SiteLookup;
  $queryRaw(query: TemplateStringsArray, ...values: unknown[]): PromiseLike<unknown>;
}

export interface PrismaScanClient {
  readonly scan: ScanDelegate;
  readonly site: SiteLookup;
  $transaction<R>(fn: (tx: PrismaScanTransaction) => Promise<R>): Promise<R>;
}

function activeWhere(now: Date, limits: CreateScanLimits): ActiveWhere {
  return {
    status: { in: [...ACTIVE_STATUSES] },
    createdAt: { gt: new Date(now.getTime() - limits.activeWindowMs) },
  };
}

function historyWhere(
  ownerId: string,
  siteId: string,
  after: ScanCursor | undefined,
): HistoryWhere {
  const where: HistoryWhere = { siteId, site: { ownerId } };
  if (after === undefined) return where;
  // Keyset pagination on (created_at DESC, id DESC), served by the
  // scans(site_id, created_at DESC) index: rows strictly after the cursor.
  return {
    ...where,
    OR: [
      { createdAt: { lt: after.createdAt } },
      { createdAt: after.createdAt, id: { lt: after.id } },
    ],
  };
}

export function createPrismaScanStore(
  client: PrismaScanClient,
  now: () => Date = () => new Date(),
): ScanStore {
  return {
    async createScan(ownerId, siteId, trigger, limits) {
      const attempt = () =>
        client.$transaction(async (tx) => {
          // Lock the owner's row first, as site creation does: one user's scan
          // requests queue up here, so two can't both pass the per-user limit.
          await tx.$queryRaw`SELECT 1 FROM "users" WHERE "id" = ${ownerId}::uuid FOR UPDATE`;
          const site = await tx.site.findFirst({
            where: { id: siteId, ownerId },
            select: { id: true, url: true },
          });
          if (site === null) return { kind: "site_not_found" } as const;
          const at = now();
          const active = activeWhere(at, limits);
          // Close out scans a dead worker left behind, so the partial unique
          // index (one active scan per site) doesn't block this site forever.
          await tx.scan.updateMany({
            where: {
              siteId,
              status: { in: [...ACTIVE_STATUSES] },
              createdAt: { lte: active.createdAt.gt },
            },
            data: { status: "FAILED", error: STALE_SCAN_MESSAGE, finishedAt: at },
          });
          const [running] = await tx.scan.findMany({
            where: { ...active, siteId },
            select: SCAN_SELECT,
            take: 1,
          });
          if (running !== undefined) return { kind: "in_progress", scan: running } as const;
          const count = await tx.scan.count({ where: { ...active, site: { ownerId } } });
          if (count >= limits.maxActivePerUser) {
            return { kind: "limit_reached", limit: limits.maxActivePerUser } as const;
          }
          const scan = await tx.scan.create({
            // The URL is copied from the site row now, so the job payload never carries it.
            // createdAt comes from the same clock as the active-window check above.
            data: { siteId, trigger, requestedUrl: site.url, status: "QUEUED", createdAt: at },
            select: SCAN_SELECT,
          });
          return { kind: "created", scan } as const;
        });
      try {
        return await attempt();
      } catch (error) {
        // scans_one_active_per_site_key: a concurrent request inserted first.
        // Run again; this time the check above sees that scan and reports it.
        if (isUniqueViolation(error)) return attempt();
        throw error;
      }
    },

    async listScans(ownerId, siteId, options) {
      const { after } = options;
      // Ownership is part of the query (a join on sites.owner_id), not a
      // separate check whose result the query trusts.
      const rows = await client.scan.findMany({
        where: historyWhere(ownerId, siteId, after),
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        take: options.limit,
        select: SCAN_SELECT,
      });
      if (rows.length > 0) return rows;
      // Empty page: "no (more) scans" or "not your site"? Only then ask.
      const site = await client.site.findFirst({
        where: { id: siteId, ownerId },
        select: { id: true, url: true },
      });
      return site === null ? null : [];
    },

    async findScan(ownerId, siteId, scanId): Promise<ScanDetail | null> {
      const row = await client.scan.findFirst({
        where: { id: scanId, siteId, site: { ownerId } },
        select: {
          ...SCAN_SELECT,
          report: true,
          findings: { select: FINDING_SELECT, orderBy: { position: "asc" } },
        },
      });
      return row;
    },

    async failQueuedScan(scanId, error, at) {
      await client.scan.updateMany({
        where: { id: scanId, status: "QUEUED" },
        data: { status: "FAILED", error, finishedAt: at },
      });
    },
  };
}
