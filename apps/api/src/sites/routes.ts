/**
 * Sites CRUD, owner-scoped.
 *
 *   GET    /sites            newest first, cursor-paginated
 *   POST   /sites            201 + Location
 *   GET    /sites/:id
 *   PATCH  /sites/:id        name, schedule, firstPartyHosts (the URL is immutable)
 *   DELETE /sites/:id        204
 *   POST   /sites/:id/verify check the DNS TXT record and mark the site verified
 *
 * Authorization model: every route starts with `requireAuth`, and every store
 * call passes the signed-in user's id. A site that exists but belongs to
 * someone else gets exactly the same 404 as one that doesn't exist, so ids
 * can't be probed to learn what other users monitor.
 */
import { randomBytes } from "node:crypto";

import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";

import { requireAuth } from "../auth/plugin.js";
import { MemoryRateLimiter, type RateLimiter } from "../auth/rate-limit.js";
import type { SitesConfig } from "../config.js";
import { AppError } from "../errors.js";
import {
  type DomainVerifier,
  type VerificationRecord,
  verificationRecordOrNull,
  type VerificationResult,
  VerificationUnsupportedError,
} from "../verification/domain.js";
import { decodeCursor, encodeCursor } from "./cursor.js";
import {
  type Schedule,
  SiteExistsError,
  SiteLimitError,
  type SiteRecord,
  type SiteStore,
} from "./store.js";
import { normalizeHostname, normalizeSiteUrl, type SiteUrlOptions } from "./url.js";

export interface SitesOptions {
  readonly store: SiteStore;
  /** Enables POST /sites/:id/verify. Omit and the route is not registered. */
  readonly verification?: VerificationOptions;
}

export interface VerificationOptions {
  readonly verifier: DomainVerifier;
  /** Defaults to an in-process limiter using `sites.verification.windowMs`. */
  readonly rateLimiter?: RateLimiter;
  readonly now?: () => Date;
}

export interface PublicSite {
  readonly id: string;
  readonly name: string;
  readonly url: string;
  readonly schedule: Lowercase<Schedule>;
  /** When the next scheduled scan is queued; null without a schedule. */
  readonly nextScanAt: string | null;
  readonly firstPartyHosts: readonly string[];
  readonly verified: boolean;
  readonly verifiedAt: string | null;
  /** Published by the owner in a DNS TXT record to prove control. */
  readonly verificationToken: string;
  /** The exact record to publish; null when the host can't be verified over DNS (IP, localhost). */
  readonly verificationRecord: VerificationRecord | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface SitePage {
  readonly items: readonly PublicSite[];
  /** Pass as `?cursor=` for the next page; null on the last page. */
  readonly nextCursor: string | null;
}

export const SITE_NAME_MAX_LENGTH = 100;
export const FIRST_PARTY_HOSTS_MAX = 20;
export const DEFAULT_PAGE_SIZE = 20;
export const MAX_PAGE_SIZE = 100;
/** 32 random bytes as hex: 64 characters, fits VARCHAR(64) and a DNS TXT string. */
export const VERIFICATION_TOKEN_BYTES = 32;

export function generateVerificationToken(): string {
  return randomBytes(VERIFICATION_TOKEN_BYTES).toString("hex");
}

export function toPublicSite(site: SiteRecord): PublicSite {
  return {
    id: site.id,
    name: site.name,
    url: site.url,
    schedule: site.schedule.toLowerCase() as Lowercase<Schedule>,
    nextScanAt: site.nextScanAt?.toISOString() ?? null,
    firstPartyHosts: [...site.firstPartyHosts],
    verified: site.verifiedAt !== null,
    verifiedAt: site.verifiedAt?.toISOString() ?? null,
    verificationToken: site.verificationToken,
    verificationRecord: verificationRecordOrNull(site.url, site.verificationToken),
    createdAt: site.createdAt.toISOString(),
    updatedAt: site.updatedAt.toISOString(),
  };
}

const nameSchema = z
  .string()
  .transform((value) => value.normalize("NFC").trim())
  .pipe(
    z
      .string()
      .min(1, "is required")
      .max(SITE_NAME_MAX_LENGTH, `must be at most ${String(SITE_NAME_MAX_LENGTH)} characters`)
      // eslint-disable-next-line no-control-regex
      .regex(/^[^\u0000-\u001f\u007f]*$/, "must not contain control characters"),
  );

const scheduleSchema = z
  .enum(["none", "daily", "weekly"])
  .transform((value) => value.toUpperCase() as Schedule);

const hostsSchema = z
  .array(z.string().max(300, "is too long"))
  .max(FIRST_PARTY_HOSTS_MAX, `must have at most ${String(FIRST_PARTY_HOSTS_MAX)} entries`)
  .transform((hosts, ctx) => {
    const normalized: string[] = [];
    hosts.forEach((host, index) => {
      const result = normalizeHostname(host);
      if (result.ok) normalized.push(result.value);
      else ctx.addIssue({ code: "custom", message: result.reason, path: [index] });
    });
    return [...new Set(normalized)];
  });

function urlSchema(options: SiteUrlOptions) {
  return z
    .string()
    .max(4_096, "is too long")
    .transform((value, ctx) => {
      const result = normalizeSiteUrl(value, options);
      if (result.ok) return result.value;
      ctx.addIssue({ code: "custom", message: result.reason });
      return z.NEVER;
    });
}

const idParams = z.object({ id: z.string() });

const listQuery = z.strictObject({
  limit: z.coerce
    .number()
    .int("must be an integer")
    .min(1, "must be at least 1")
    .max(MAX_PAGE_SIZE, `must be at most ${String(MAX_PAGE_SIZE)}`)
    .default(DEFAULT_PAGE_SIZE),
  cursor: z.string().optional(),
});

const patchBody = z
  .strictObject({
    name: nameSchema.optional(),
    schedule: scheduleSchema.optional(),
    firstPartyHosts: hostsSchema.optional(),
  })
  .refine((patch) => Object.values(patch).some((value) => value !== undefined), {
    message: "must change at least one field",
  });

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Lower-case canonical UUID, as Postgres prints them. */
export function isUuid(value: string): boolean {
  return UUID.test(value);
}

function notFound(): AppError {
  return new AppError(404, "SITE_NOT_FOUND", "Site not found");
}

/** A malformed id can't match anything; answer 404 like any other miss. */
function siteId(request: FastifyRequest): string {
  const id = idParams.parse(request.params).id.toLowerCase();
  if (!isUuid(id)) throw notFound();
  return id;
}

function requireVerifiedForSchedule(schedule: Schedule, site: SiteRecord | null): void {
  if (schedule !== "NONE" && (site === null || site.verifiedAt === null)) {
    throw new AppError(
      409,
      "SITE_NOT_VERIFIED",
      "Verify ownership of this domain before enabling scheduled scans",
    );
  }
}

/** 422/503 for a check that didn't verify; the message says what to fix. */
function verificationFailed(result: Exclude<VerificationResult, { status: "VERIFIED" }>): AppError {
  const { name, value } = result.record;
  switch (result.status) {
    case "RECORD_MISSING":
      return new AppError(
        422,
        "VERIFICATION_RECORD_MISSING",
        `No verification record found. Add a TXT record at ${name} with the value ${value}, then try again. DNS changes can take a few minutes to appear.`,
      );
    case "TOKEN_MISMATCH":
      return new AppError(
        422,
        "VERIFICATION_TOKEN_MISMATCH",
        `The TXT record at ${name} has a different token. Set its value to ${value}, then try again.`,
      );
    case "DNS_ERROR":
      // 5xx: the client sees a generic message; the DNS error code is logged.
      return new AppError(503, "VERIFICATION_DNS_UNAVAILABLE", `DNS lookup failed: ${result.code}`);
  }
}

function registerVerifyRoute(
  app: FastifyInstance,
  config: SitesConfig,
  store: SiteStore,
  options: VerificationOptions,
): void {
  const { verifier } = options;
  const limits = config.verification;
  const limiter = options.rateLimiter ?? new MemoryRateLimiter({ windowMs: limits.windowMs });
  const now = options.now ?? (() => new Date());

  app.post("/sites/:id/verify", async (request, reply) => {
    const { user } = requireAuth(request);
    const id = siteId(request);
    const site = await store.findSite(user.id, id);
    if (site === null) throw notFound();
    // Already verified: nothing to prove, no DNS query, and no attempt counted.
    if (site.verifiedAt !== null) return toPublicSite(site);

    // Every real check sends a DNS query for a name the user chose, so it is
    // rate-limited per account (not per site: adding sites mustn't add budget).
    const decision = await limiter.consume(`verify:user:${user.id}`, limits.attemptsPerWindow);
    if (!decision.allowed) {
      void reply.header(
        "retry-after",
        String(Math.max(1, Math.ceil(decision.retryAfterMs / 1_000))),
      );
      throw new AppError(429, "RATE_LIMITED", "Too many verification attempts. Try again later.");
    }

    let result: VerificationResult;
    try {
      result = await verifier.verify(site.url, site.verificationToken);
    } catch (error) {
      if (error instanceof VerificationUnsupportedError) {
        throw new AppError(422, "VERIFICATION_UNSUPPORTED", error.message);
      }
      throw error;
    }
    request.log.info(
      { userId: user.id, siteId: id, outcome: result.status, record: result.record.name },
      "site verification checked",
    );
    if (result.status !== "VERIFIED") throw verificationFailed(result);

    const verified = await store.recordVerification(user.id, id, site.verificationToken, now());
    if (verified === null) throw notFound();
    return toPublicSite(verified);
  });
}

export function registerSiteRoutes(
  app: FastifyInstance,
  config: SitesConfig,
  options: SitesOptions,
): void {
  const { store } = options;
  const createBody = z.strictObject({
    name: nameSchema,
    url: urlSchema({ allowPrivateTargets: config.allowPrivateTargets }),
    schedule: scheduleSchema.default("NONE"),
    firstPartyHosts: hostsSchema.default([]),
  });

  app.get("/sites", async (request): Promise<SitePage> => {
    const { user } = requireAuth(request);
    const query = listQuery.parse(request.query);
    let after;
    if (query.cursor !== undefined) {
      after = decodeCursor(query.cursor);
      if (after === undefined) {
        throw new AppError(400, "VALIDATION_FAILED", "Request validation failed", {
          details: [{ path: "cursor", message: "is not a valid cursor" }],
        });
      }
    }
    // Fetch one extra row to learn whether another page exists without a COUNT.
    const rows = await store.listSites(user.id, {
      limit: query.limit + 1,
      ...(after === undefined ? {} : { after }),
    });
    const page = rows.slice(0, query.limit);
    const last = page.at(-1);
    return {
      items: page.map(toPublicSite),
      nextCursor: rows.length > query.limit && last !== undefined ? encodeCursor(last) : null,
    };
  });

  app.post("/sites", async (request, reply) => {
    const { user } = requireAuth(request);
    const body = createBody.parse(request.body);
    // A brand-new site is never verified, so it can't start on a schedule.
    requireVerifiedForSchedule(body.schedule, null);
    let site: SiteRecord;
    try {
      site = await store.createSite(
        { ownerId: user.id, ...body, verificationToken: generateVerificationToken() },
        config.maxPerUser,
      );
    } catch (error) {
      if (error instanceof SiteExistsError) {
        throw new AppError(409, "SITE_EXISTS", "You have already added this site");
      }
      if (error instanceof SiteLimitError) {
        throw new AppError(
          409,
          "SITE_LIMIT_REACHED",
          `You can add at most ${String(error.limit)} sites`,
        );
      }
      throw error;
    }
    request.log.info({ userId: user.id, siteId: site.id }, "site created");
    return reply.status(201).header("location", `/sites/${site.id}`).send(toPublicSite(site));
  });

  app.get("/sites/:id", async (request) => {
    const { user } = requireAuth(request);
    const site = await store.findSite(user.id, siteId(request));
    if (site === null) throw notFound();
    return toPublicSite(site);
  });

  app.patch("/sites/:id", async (request) => {
    const { user } = requireAuth(request);
    const id = siteId(request);
    const patch = patchBody.parse(request.body);
    if (patch.schedule !== undefined) {
      const current = await store.findSite(user.id, id);
      if (current === null) throw notFound();
      requireVerifiedForSchedule(patch.schedule, current);
    }
    const site = await store.updateSite(user.id, id, patch);
    if (site === null) throw notFound();
    request.log.info({ userId: user.id, siteId: site.id }, "site updated");
    return toPublicSite(site);
  });

  app.delete("/sites/:id", async (request, reply) => {
    const { user } = requireAuth(request);
    const id = siteId(request);
    if (!(await store.deleteSite(user.id, id))) throw notFound();
    request.log.info({ userId: user.id, siteId: id }, "site deleted");
    return reply.status(204).send();
  });

  if (options.verification !== undefined) {
    registerVerifyRoute(app, config, store, options.verification);
  }
}
