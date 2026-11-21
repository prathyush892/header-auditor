/**
 * Health endpoints, split the way orchestrators expect:
 *
 * - GET /health        liveness: the process is up and the event loop answers.
 *                      Never touches dependencies, so a database outage doesn't
 *                      get every API container restarted.
 * - GET /health/ready  readiness: every registered dependency check passed
 *                      within its timeout. 503 takes the instance out of the
 *                      load balancer until it recovers.
 *
 * Check errors are logged, never returned: the endpoint is unauthenticated, and
 * a driver error message can reveal hostnames or versions.
 */
import type { FastifyInstance } from "fastify";

export interface HealthCheck {
  /** Short identifier shown in the response, e.g. "database". */
  readonly name: string;
  /** Resolves when healthy; rejects (or exceeds the timeout) when not. */
  readonly check: (signal: AbortSignal) => Promise<void>;
}

export type CheckStatus = "ok" | "fail";

export interface ReadinessResult {
  readonly status: "ok" | "unavailable";
  readonly checks: Readonly<Record<string, CheckStatus>>;
}

const CHECK_NAME = /^[a-z][a-z0-9_-]{0,31}$/;

/** Rejects bad or duplicate names at startup, not on the first probe. */
export function validateHealthChecks(checks: readonly HealthCheck[]): void {
  const seen = new Set<string>();
  for (const { name } of checks) {
    if (!CHECK_NAME.test(name)) {
      throw new TypeError(`Invalid health check name ${JSON.stringify(name)}`);
    }
    if (seen.has(name)) throw new TypeError(`Duplicate health check name "${name}"`);
    seen.add(name);
  }
}

export class HealthCheckTimeoutError extends Error {
  override readonly name = "HealthCheckTimeoutError";
}

/** Runs one check, aborting it and failing once `timeoutMs` passes. */
export async function runCheck(check: HealthCheck, timeoutMs: number): Promise<void> {
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const error = new HealthCheckTimeoutError(
        `"${check.name}" timed out after ${String(timeoutMs)}ms`,
      );
      controller.abort(error);
      reject(error);
    }, timeoutMs);
  });
  try {
    // Promise.resolve().then() also turns a synchronous throw into a rejection.
    await Promise.race([Promise.resolve().then(() => check.check(controller.signal)), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

export interface HealthRoutesOptions {
  readonly checks: readonly HealthCheck[];
  readonly timeoutMs: number;
}

export function registerHealthRoutes(app: FastifyInstance, options: HealthRoutesOptions): void {
  validateHealthChecks(options.checks);

  app.get("/health", () => ({ status: "ok", uptimeSeconds: Math.floor(process.uptime()) }));

  app.get("/health/ready", async (request, reply): Promise<ReadinessResult> => {
    const outcomes = await Promise.allSettled(
      options.checks.map((check) => runCheck(check, options.timeoutMs)),
    );
    const entries = options.checks.map(({ name }, index): [string, CheckStatus] => {
      const outcome = outcomes.at(index);
      if (outcome?.status === "fulfilled") return [name, "ok"];
      request.log.warn({ err: outcome?.reason, check: name }, "readiness check failed");
      return [name, "fail"];
    });
    const healthy = entries.every(([, status]) => status === "ok");
    void reply.status(healthy ? 200 : 503);
    return { status: healthy ? "ok" : "unavailable", checks: Object.fromEntries(entries) };
  });
}
