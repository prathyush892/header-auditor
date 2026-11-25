import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { loadWorkerConfig, WORKER_CONFIG_KEYS, WorkerConfigError } from "../src/config.js";

const BASE = {
  DATABASE_URL: "postgresql://u:dbsecret@127.0.0.1:5432/db",
  REDIS_URL: "redis://:redissecret@127.0.0.1:6379",
};

function problems(env: Record<string, string>): readonly string[] {
  try {
    loadWorkerConfig({ ...BASE, ...env });
  } catch (error) {
    if (error instanceof WorkerConfigError) return error.problems;
    throw error;
  }
  return [];
}

describe("loadWorkerConfig", () => {
  it("applies safe defaults", () => {
    expect(loadWorkerConfig(BASE)).toEqual({
      nodeEnv: "development",
      logLevel: "info",
      databaseUrl: BASE.DATABASE_URL,
      redisUrl: BASE.REDIS_URL,
      queuePrefix: "header-auditor",
      concurrency: 4,
      scanTimeoutMs: 30_000,
      staleAfterMs: 300_000,
      shutdownTimeoutMs: 60_000,
      allowPrivateTargets: false,
    });
  });

  it("requires DATABASE_URL and REDIS_URL", () => {
    expect(() => loadWorkerConfig({})).toThrow(WorkerConfigError);
    const keys = (() => {
      try {
        loadWorkerConfig({ REDIS_URL: "", DATABASE_URL: " " });
      } catch (error) {
        return (error as WorkerConfigError).problems.map((p) => p.split(":")[0]);
      }
      return [];
    })();
    expect(keys.sort()).toEqual(["DATABASE_URL", "REDIS_URL"]);
  });

  it.each([
    ["REDIS_URL", "http://127.0.0.1:6379"],
    ["DATABASE_URL", "mysql://127.0.0.1/db"],
    ["WORKER_CONCURRENCY", "0"],
    ["WORKER_CONCURRENCY", "51"],
    ["WORKER_SCAN_TIMEOUT_MS", "500"],
    ["WORKER_SCAN_TIMEOUT_MS", "120001"],
    ["WORKER_ALLOW_PRIVATE_TARGETS", "yes"],
    ["QUEUE_PREFIX", "a:b"],
    ["LOG_LEVEL", "verbose"],
  ])("rejects %s=%s", (key, value) => {
    const found = problems({ [key]: value });
    expect(found).toHaveLength(1);
    expect(found[0]?.startsWith(`${key}: `)).toBe(true);
  });

  it("never echoes secrets in errors", () => {
    const error = (() => {
      try {
        loadWorkerConfig({
          DATABASE_URL: "mysql://u:dbsecret@h/db",
          REDIS_URL: "x://:redissecret@h",
        });
      } catch (caught) {
        return caught as Error;
      }
      throw new Error("expected a config error");
    })();
    expect(error.message).not.toContain("dbsecret");
    expect(error.message).not.toContain("redissecret");
  });

  it("refuses private targets in production", () => {
    expect(problems({ NODE_ENV: "production", WORKER_ALLOW_PRIVATE_TARGETS: "true" })).toEqual([
      "WORKER_ALLOW_PRIVATE_TARGETS: must be false in production",
    ]);
    expect(problems({ NODE_ENV: "development", WORKER_ALLOW_PRIVATE_TARGETS: "true" })).toEqual([]);
  });

  it("requires the stale window to exceed a full scan, so live scans are never re-claimed", () => {
    expect(
      problems({ WORKER_SCAN_TIMEOUT_MS: "60000", WORKER_STALE_AFTER_SECONDS: "120" }),
    ).toEqual([expect.stringMatching(/^WORKER_STALE_AFTER_SECONDS: must exceed/)]);
    expect(
      problems({ WORKER_SCAN_TIMEOUT_MS: "60000", WORKER_STALE_AFTER_SECONDS: "121" }),
    ).toEqual([]);
  });

  it("ignores unknown variables and treats blank values as unset", () => {
    const config = loadWorkerConfig({ ...BASE, WORKER_CONCURRENCY: " ", UNRELATED: "x" });
    expect(config.concurrency).toBe(4);
  });
});

describe(".env.example", () => {
  it("documents every worker variable with values that load to the defaults", () => {
    // Fixed repo file, not user input.
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const text = readFileSync(new URL("../../../.env.example", import.meta.url), "utf8");
    const env = Object.fromEntries(
      text
        .split("\n")
        .filter((line) => /^[A-Z_]+=/.test(line))
        .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
    );
    for (const key of WORKER_CONFIG_KEYS) expect(env).toHaveProperty(key);
    const { DATABASE_URL, REDIS_URL } = env;
    expect(loadWorkerConfig({ ...env, NODE_ENV: "development" })).toEqual(
      loadWorkerConfig({ DATABASE_URL, REDIS_URL }),
    );
  });
});
