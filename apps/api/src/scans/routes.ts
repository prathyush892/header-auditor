/**
 * Scan routes, owner-scoped like /sites.
 *
 *   POST /sites/:id/scans           202 + Location: queue a scan of the site
 *   GET  /sites/:id/scans           history, newest first, cursor-paginated
 *   GET  /sites/:id/scans/:scanId   status, and once finished the full result
 *
 * The request only records intent (a QUEUED row) and hands the id to the
 * worker. Scanning a site can take tens of seconds, far longer than an HTTP
 * request should be held open, and the API process should never be the one
 * making outbound requests to arbitrary hosts.
 */
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";

import { requireAuth } from "../auth/plugin.js";
import type { ScansConfig } from "../config.js";
import { AppError } from "../errors.js";
import { decodeCursor, encodeCursor } from "../sites/cursor.js";
import { DEFAULT_PAGE_SIZE, isUuid, MAX_PAGE_SIZE } from "../sites/routes.js";
import type { ScanQueue } from "./queue.js";
import {
  ENQUEUE_FAILED_MESSAGE,
  type FindingRecord,
  type ScanDetail,
  type ScanRecord,
  type ScanStore,
} from "./store.js";

export interface ScansOptions {
  readonly store: ScanStore;
  readonly queue: ScanQueue;
  readonly now?: () => Date;
}

export interface PublicFinding {
  readonly category: Lowercase<FindingRecord["category"]>;
  readonly check: string;
  readonly status: Lowercase<FindingRecord["status"]>;
  readonly detail: string;
  readonly weight: number;
  readonly score: number;
  readonly recommendation: string;
}

export interface PublicScan {
  readonly id: string;
  readonly siteId: string;
  readonly status: Lowercase<ScanRecord["status"]>;
  readonly trigger: Lowercase<ScanRecord["trigger"]>;
  readonly requestedUrl: string;
  readonly finalUrl: string | null;
  readonly httpStatus: number | null;
  readonly score: number | null;
  readonly grade: ScanRecord["grade"];
  readonly engineVersion: string | null;
  readonly error: string | null;
  readonly createdAt: string;
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
}

export interface ScanPage {
  /** Summaries only: fetch /sites/:id/scans/:scanId for findings and the report. */
  readonly items: readonly PublicScan[];
  /** Pass as `?cursor=` for the next page; null on the last page. */
  readonly nextCursor: string | null;
}

export interface PublicScanDetail extends PublicScan {
  readonly report: unknown;
  readonly findings: readonly PublicFinding[];
}

export function toPublicScan(scan: ScanRecord): PublicScan {
  return {
    id: scan.id,
    siteId: scan.siteId,
    status: scan.status.toLowerCase() as PublicScan["status"],
    trigger: scan.trigger.toLowerCase() as PublicScan["trigger"],
    requestedUrl: scan.requestedUrl,
    finalUrl: scan.finalUrl,
    httpStatus: scan.httpStatus,
    score: scan.score,
    grade: scan.grade,
    engineVersion: scan.engineVersion,
    error: scan.error,
    createdAt: scan.createdAt.toISOString(),
    startedAt: scan.startedAt?.toISOString() ?? null,
    finishedAt: scan.finishedAt?.toISOString() ?? null,
  };
}

export function toPublicScanDetail(scan: ScanDetail): PublicScanDetail {
  return {
    ...toPublicScan(scan),
    report: scan.report,
    findings: scan.findings.map((f) => ({
      category: f.category.toLowerCase() as PublicFinding["category"],
      check: f.check,
      status: f.status.toLowerCase() as PublicFinding["status"],
      detail: f.detail,
      weight: f.weight,
      score: f.score,
      recommendation: f.recommendation,
    })),
  };
}

const siteParams = z.object({ id: z.string() });
const scanParams = z.object({ id: z.string(), scanId: z.string() });
const historyQuery = z.strictObject({
  limit: z.coerce
    .number()
    .int("must be an integer")
    .min(1, "must be at least 1")
    .max(MAX_PAGE_SIZE, `must be at most ${String(MAX_PAGE_SIZE)}`)
    .default(DEFAULT_PAGE_SIZE),
  cursor: z.string().optional(),
});
/** POST takes no options yet; reject a body rather than ignore one a client thinks matters. */
const createBody = z.union([z.undefined(), z.null(), z.strictObject({})]);

function siteNotFound(): AppError {
  return new AppError(404, "SITE_NOT_FOUND", "Site not found");
}

function scanNotFound(): AppError {
  return new AppError(404, "SCAN_NOT_FOUND", "Scan not found");
}

/** Malformed ids get the same 404 as unknown ones, like /sites/:id. */
function uuidOr404(value: string, notFound: () => AppError): string {
  const id = value.toLowerCase();
  if (!isUuid(id)) throw notFound();
  return id;
}

function scanLocation(scan: ScanRecord): string {
  return `/sites/${scan.siteId}/scans/${scan.id}`;
}

export function registerScanRoutes(
  app: FastifyInstance,
  config: ScansConfig,
  options: ScansOptions,
): void {
  const { store, queue } = options;
  const now = options.now ?? (() => new Date());
  const limits = {
    maxActivePerUser: config.maxActivePerUser,
    activeWindowMs: config.activeWindowMs,
  };

  app.post("/sites/:id/scans", async (request: FastifyRequest, reply) => {
    const { user } = requireAuth(request);
    const siteId = uuidOr404(siteParams.parse(request.params).id, siteNotFound);
    createBody.parse(request.body);

    const result = await store.createScan(user.id, siteId, "MANUAL", limits);
    switch (result.kind) {
      case "site_not_found":
        throw siteNotFound();
      case "in_progress":
        // Point the client at the scan it should poll instead of starting another.
        void reply.header("location", scanLocation(result.scan));
        throw new AppError(409, "SCAN_IN_PROGRESS", "A scan of this site is already in progress");
      case "limit_reached":
        throw new AppError(
          429,
          "SCAN_LIMIT_REACHED",
          `You can have at most ${String(result.limit)} scans queued or running at once`,
        );
      case "created":
        break;
    }

    const { scan } = result;
    try {
      await queue.enqueue(scan.id);
    } catch (error) {
      // The row exists but no worker will ever see it. Mark it FAILED so the
      // site isn't blocked by a phantom "in progress" scan, then report 503.
      await store.failQueuedScan(scan.id, ENQUEUE_FAILED_MESSAGE, now());
      throw new AppError(503, "QUEUE_UNAVAILABLE", "Scan queue unavailable", { cause: error });
    }
    request.log.info({ userId: user.id, siteId, scanId: scan.id }, "scan queued");
    return reply.status(202).header("location", scanLocation(scan)).send(toPublicScan(scan));
  });

  app.get("/sites/:id/scans", async (request): Promise<ScanPage> => {
    const { user } = requireAuth(request);
    const siteId = uuidOr404(siteParams.parse(request.params).id, siteNotFound);
    const query = historyQuery.parse(request.query);
    let after;
    if (query.cursor !== undefined) {
      after = decodeCursor(query.cursor);
      if (after === undefined) {
        throw new AppError(400, "VALIDATION_FAILED", "Request validation failed", {
          details: [{ path: "cursor", message: "is not a valid cursor" }],
        });
      }
    }
    // One extra row tells us whether another page exists, without a COUNT.
    const rows = await store.listScans(user.id, siteId, {
      limit: query.limit + 1,
      ...(after === undefined ? {} : { after }),
    });
    if (rows === null) throw siteNotFound();
    const page = rows.slice(0, query.limit);
    const last = page.at(-1);
    return {
      items: page.map(toPublicScan),
      nextCursor: rows.length > query.limit && last !== undefined ? encodeCursor(last) : null,
    };
  });

  app.get("/sites/:id/scans/:scanId", async (request) => {
    const { user } = requireAuth(request);
    const params = scanParams.parse(request.params);
    const siteId = uuidOr404(params.id, scanNotFound);
    const scanId = uuidOr404(params.scanId, scanNotFound);
    const scan = await store.findScan(user.id, siteId, scanId);
    if (scan === null) throw scanNotFound();
    return toPublicScanDetail(scan);
  });
}
