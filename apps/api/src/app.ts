/**
 * Builds the Fastify instance without listening on a port.
 *
 * Keeping construction separate from `listen()` is what makes the API
 * testable: tests call `buildApp()` and drive it with `app.inject()`, which
 * runs the full request lifecycle (hooks, validation, error handler,
 * serialization) in memory, with no sockets and no port conflicts.
 */
import Fastify, { type FastifyInstance } from "fastify";

import { type AuthOptions, registerAuth } from "./auth/plugin.js";
import type { ApiConfig } from "./config.js";
import { errorHandler, notFoundHandler } from "./errors.js";
import { type HealthCheck, registerHealthRoutes } from "./health.js";
import { registerScanRoutes, type ScansOptions } from "./scans/routes.js";
import { registerSiteRoutes, type SitesOptions } from "./sites/routes.js";
import {
  generateRequestId,
  type LoggerOverrides,
  loggerOptions,
  REQUEST_ID_HEADER,
} from "./logger.js";

export interface BuildAppOptions {
  readonly config: ApiConfig;
  /** Dependency checks for /health/ready (database, Redis, ...). */
  readonly healthChecks?: readonly HealthCheck[];
  readonly logger?: LoggerOverrides;
  /** Enables /auth/* routes and session/CSRF hooks. Omit for a bare skeleton. */
  readonly auth?: AuthOptions;
  /** Enables /sites routes. Requires `auth`: every site belongs to a signed-in user. */
  readonly sites?: SitesOptions;
  /** Enables /sites/:id/scans routes. Requires `sites`. */
  readonly scans?: ScansOptions;
}

/**
 * Baseline headers for a JSON API. The API never serves HTML, so the strictest
 * CSP costs nothing; helmet replaces this in roadmap step 24.
 */
export const BASELINE_HEADERS: Readonly<Record<string, string>> = {
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
  "cross-origin-resource-policy": "same-origin",
};

export async function buildApp(options: BuildAppOptions): Promise<FastifyInstance> {
  const { config } = options;
  if (options.sites !== undefined && options.auth === undefined) {
    throw new TypeError("buildApp: `sites` requires `auth` (sites are owned by signed-in users)");
  }
  if (options.scans !== undefined && options.sites === undefined) {
    throw new TypeError("buildApp: `scans` requires `sites` (scans belong to a site)");
  }
  const app = Fastify({
    logger: loggerOptions(config, options.logger),
    genReqId: generateRequestId,
    trustProxy: config.trustProxy,
    bodyLimit: config.bodyLimitBytes,
    requestTimeout: config.requestTimeoutMs,
    // While closing, new requests get 503 so load balancers drain this instance.
    return503OnClosing: true,
    routerOptions: { maxParamLength: 200 },
  });

  app.addHook("onRequest", async (request, reply) => {
    void reply.header(REQUEST_ID_HEADER, request.id);
    for (const [name, value] of Object.entries(BASELINE_HEADERS)) void reply.header(name, value);
    // API responses are per-user data; never let a shared cache keep them.
    void reply.header("cache-control", "no-store");
  });

  // JSON only. Fastify also parses text/plain by default, and text/plain is a
  // CORS "simple" content type: a cross-site <form> or fetch can send it
  // without a preflight. Dropping the parser turns those into 415s.
  app.removeContentTypeParser("text/plain");

  app.setErrorHandler(errorHandler);
  app.setNotFoundHandler(notFoundHandler);

  if (options.auth !== undefined) await registerAuth(app, config, options.auth);
  if (options.sites !== undefined) registerSiteRoutes(app, config.sites, options.sites);
  if (options.scans !== undefined) registerScanRoutes(app, config.scans, options.scans);

  registerHealthRoutes(app, {
    checks: options.healthChecks ?? [],
    timeoutMs: config.readinessTimeoutMs,
  });

  return app;
}
