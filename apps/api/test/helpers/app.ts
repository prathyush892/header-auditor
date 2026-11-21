import { Writable } from "node:stream";

import type { FastifyInstance } from "fastify";

import { buildApp, type BuildAppOptions } from "../../src/app.js";
import { type ApiConfig, type Env, loadConfig } from "../../src/config.js";

export function testConfig(env: Env = {}): ApiConfig {
  return loadConfig({ NODE_ENV: "test", LOG_LEVEL: "silent", ...env });
}

/** Collects pino's JSON lines so tests can assert on what was logged. */
export class LogCapture extends Writable {
  readonly lines: Record<string, unknown>[] = [];
  readonly raw: string[] = [];

  override _write(
    chunk: Buffer,
    _encoding: BufferEncoding,
    done: (error?: Error | null) => void,
  ): void {
    for (const line of chunk.toString("utf8").split("\n")) {
      if (line.trim() === "") continue;
      this.raw.push(line);
      this.lines.push(JSON.parse(line) as Record<string, unknown>);
    }
    done();
  }

  text(): string {
    return this.raw.join("\n");
  }
}

export interface TestApp {
  readonly app: FastifyInstance;
  readonly logs: LogCapture;
}

/**
 * App with logging at `info` into a LogCapture. `setup` registers extra
 * test-only routes before the app is ready.
 */
export async function createTestApp(
  options: Omit<BuildAppOptions, "config" | "logger"> & {
    readonly env?: Env;
    readonly setup?: (app: FastifyInstance) => void;
  } = {},
): Promise<TestApp> {
  const { env, setup, ...rest } = options;
  const logs = new LogCapture();
  const app = await buildApp({
    ...rest,
    config: testConfig({ LOG_LEVEL: "info", ...env }),
    logger: { stream: logs },
  });
  setup?.(app);
  await app.ready();
  return { app, logs };
}
