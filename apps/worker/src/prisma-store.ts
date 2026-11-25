/**
 * `WorkerScanStore` on PostgreSQL through Prisma. The client is typed
 * structurally (like the API's stores) and tests pass the generated client.
 */
import type { FindingRow } from "@header-auditor/db";

import type { ClaimedScan, ScanLease, ScanSuccess, WorkerScanStore } from "./store.js";

type Json = string | number | boolean | Json[] | { [key: string]: Json | null };

type ClaimWhere = {
  id: string;
  OR: [{ status: "QUEUED" }, { status: "RUNNING"; startedAt: { lt: Date } }];
};
type LeaseWhere = { id: string; status: "RUNNING"; startedAt: Date };
type ActiveWhere = { id: string; status: { in: ["QUEUED", "RUNNING"] } };

interface ScanDelegate {
  updateMany(args: {
    where: ClaimWhere | LeaseWhere | ActiveWhere;
    data:
      | { status: "RUNNING"; startedAt: Date }
      | { status: "QUEUED"; startedAt: null }
      | {
          status: "SUCCEEDED";
          finishedAt: Date;
          finalUrl: string;
          httpStatus: number;
          score: number;
          grade: ScanSuccess["grade"];
          engineVersion: string;
          report: Json;
          error: null;
        }
      | { status: "FAILED"; finishedAt: Date; error: string };
  }): PromiseLike<{ count: number }>;
  findFirst(args: {
    where: { id: string; status: "RUNNING"; startedAt: Date };
    select: {
      id: true;
      siteId: true;
      requestedUrl: true;
      site: { select: { firstPartyHosts: true } };
    };
  }): PromiseLike<{
    id: string;
    siteId: string;
    requestedUrl: string;
    site: { firstPartyHosts: string[] };
  } | null>;
}

interface FindingDelegate {
  createMany(args: { data: (FindingRow & { scanId: string })[] }): PromiseLike<{ count: number }>;
}

export interface PrismaWorkerTransaction {
  readonly scan: ScanDelegate;
  readonly finding: FindingDelegate;
}

export interface PrismaWorkerClient {
  readonly scan: ScanDelegate;
  $transaction<R>(fn: (tx: PrismaWorkerTransaction) => Promise<R>): Promise<R>;
}

function leaseWhere(lease: ScanLease): LeaseWhere {
  return { id: lease.scanId, status: "RUNNING", startedAt: lease.startedAt };
}

/** `finished_at >= started_at` is a CHECK; don't let clock skew between hosts trip it. */
function notBefore(at: Date, lease: ScanLease): Date {
  return at.getTime() < lease.startedAt.getTime() ? lease.startedAt : at;
}

export function createPrismaWorkerStore(client: PrismaWorkerClient): WorkerScanStore {
  return {
    async claimScan(scanId, now, staleBefore): Promise<ClaimedScan | null> {
      const { count } = await client.scan.updateMany({
        where: {
          id: scanId,
          OR: [{ status: "QUEUED" }, { status: "RUNNING", startedAt: { lt: staleBefore } }],
        },
        data: { status: "RUNNING", startedAt: now },
      });
      if (count === 0) return null;
      // Read back through our own lease, so we only ever return the claim we made.
      const row = await client.scan.findFirst({
        where: { id: scanId, status: "RUNNING", startedAt: now },
        select: {
          id: true,
          siteId: true,
          requestedUrl: true,
          site: { select: { firstPartyHosts: true } },
        },
      });
      if (row === null) return null;
      return {
        scanId: row.id,
        startedAt: now,
        siteId: row.siteId,
        requestedUrl: row.requestedUrl,
        firstPartyHosts: [...row.site.firstPartyHosts],
      };
    },

    completeScan(lease, result, finishedAt) {
      return client.$transaction(async (tx) => {
        const { count } = await tx.scan.updateMany({
          where: leaseWhere(lease),
          data: {
            status: "SUCCEEDED",
            finishedAt: notBefore(finishedAt, lease),
            finalUrl: result.finalUrl,
            httpStatus: result.httpStatus,
            score: result.score,
            grade: result.grade,
            engineVersion: result.engineVersion,
            report: result.report as Json,
            error: null,
          },
        });
        if (count === 0) return false;
        if (result.findings.length > 0) {
          await tx.finding.createMany({
            data: result.findings.map((row) => ({ ...row, scanId: lease.scanId })),
          });
        }
        return true;
      });
    },

    async failScan(lease, error, finishedAt) {
      const { count } = await client.scan.updateMany({
        where: leaseWhere(lease),
        data: { status: "FAILED", finishedAt: notBefore(finishedAt, lease), error },
      });
      return count > 0;
    },

    async releaseScan(lease) {
      const { count } = await client.scan.updateMany({
        where: leaseWhere(lease),
        data: { status: "QUEUED", startedAt: null },
      });
      return count > 0;
    },

    async abandonScan(scanId, error, finishedAt) {
      const { count } = await client.scan.updateMany({
        where: { id: scanId, status: { in: ["QUEUED", "RUNNING"] } },
        data: { status: "FAILED", finishedAt, error },
      });
      return count > 0;
    },
  };
}
