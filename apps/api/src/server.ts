/**
 * Process entry point: load config, build the app, listen, and shut down
 * gracefully on SIGTERM/SIGINT (what Docker and Kubernetes send on stop).
 */
import { pathToFileURL } from "node:url";

import type { FastifyInstance } from "fastify";

import { buildApp, type BuildAppOptions } from "./app.js";
import { ConfigError, type Env, loadConfig } from "./config.js";

export type ShutdownSignal = "SIGTERM" | "SIGINT";

export interface ShutdownOptions {
  readonly timeoutMs: number;
  /** Injected so tests can observe the exit code instead of killing the runner. */
  readonly exit: (code: number) => void;
}

/**
 * Returns an idempotent shutdown function. `app.close()` stops accepting
 * connections, lets in-flight requests finish and runs onClose hooks (which is
 * where the database pool and queue connections will be closed). If that hangs,
 * a timer forces exit(1) so the orchestrator isn't left waiting forever.
 */
export function createShutdown(
  app: FastifyInstance,
  options: ShutdownOptions,
): (signal: ShutdownSignal) => Promise<void> {
  let closing: Promise<void> | undefined;
  return (signal) => {
    if (closing !== undefined) return closing;
    app.log.info({ signal }, "shutting down");
    const timer = setTimeout(() => {
      app.log.error({ timeoutMs: options.timeoutMs }, "graceful shutdown timed out");
      options.exit(1);
    }, options.timeoutMs);
    timer.unref();
    closing = app.close().then(
      () => {
        clearTimeout(timer);
        options.exit(0);
      },
      (error: unknown) => {
        clearTimeout(timer);
        app.log.error({ err: error }, "error during shutdown");
        options.exit(1);
      },
    );
    return closing;
  };
}

export interface StartOptions extends Omit<BuildAppOptions, "config"> {
  readonly env?: Env;
  /** Install SIGTERM/SIGINT handlers (off in tests). */
  readonly handleSignals?: boolean;
}

export async function start(options: StartOptions = {}): Promise<FastifyInstance> {
  const { env, handleSignals = true, ...buildOptions } = options;
  const config = loadConfig(env);
  const app = await buildApp({ ...buildOptions, config });
  if (buildOptions.auth === undefined) {
    // Until the Postgres stores are wired in at startup (roadmap step 15), the
    // caller injects one; without it /auth/* routes are simply not registered.
    app.log.warn("auth disabled: no AuthStore configured, /auth routes are not registered");
  }
  if (buildOptions.sites === undefined) {
    app.log.warn("sites disabled: no SiteStore configured, /sites routes are not registered");
  }
  if (handleSignals) {
    const shutdown = createShutdown(app, {
      timeoutMs: config.shutdownTimeoutMs,
      exit: (code) => process.exit(code),
    });
    for (const signal of ["SIGTERM", "SIGINT"] as const) {
      process.once(signal, () => void shutdown(signal));
    }
  }
  await app.listen({ host: config.host, port: config.port });
  return app;
}

function isMainModule(): boolean {
  const entry = process.argv[1];
  return entry !== undefined && import.meta.url === pathToFileURL(entry).href;
}

if (isMainModule()) {
  start().catch((error: unknown) => {
    // The logger may not exist yet (bad config), so write directly to stderr.
    const message = error instanceof ConfigError ? error.message : String(error);
    process.stderr.write(`api failed to start: ${message}\n`);
    process.exit(1);
  });
}
