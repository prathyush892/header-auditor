import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  loadSchedulerConfig,
  SCHEDULER_CONFIG_KEYS,
  SchedulerConfigError,
} from "../src/schedules/config.js";

const SECRET = "s3cret-value-that-must-not-leak";
const BASE = {
  DATABASE_URL: `postgres://app:${SECRET}@127.0.0.1:5432/header_auditor`,
  REDIS_URL: `redis://:${SECRET}@127.0.0.1:6379`,
};

function problemsOf(env: Record<string, string>): string[] {
  try {
    loadSchedulerConfig(env);
  } catch (error) {
    if (error instanceof SchedulerConfigError) return [...error.problems];
    throw error;
  }
  throw new Error("expected a SchedulerConfigError");
}

describe("loadSchedulerConfig", () => {
  it("applies defaults that match the API's scan limits", () => {
    const config = loadSchedulerConfig(BASE);
    expect(config).toMatchObject({
      queuePrefix: "header-auditor",
      intervalMs: 60_000,
      batchSize: 100,
      maxBatchesPerTick: 10,
      retryDelayMs: 15 * 60_000,
      limits: { maxActivePerUser: 5, activeWindowMs: 15 * 60_000 },
    });
    expect(Object.isFrozen(config)).toBe(true);
  });

  it("reads overrides and treats empty values as unset", () => {
    const config = loadSchedulerConfig({
      ...BASE,
      SCHEDULER_INTERVAL_SECONDS: "30",
      SCHEDULER_BATCH_SIZE: "25",
      SCHEDULER_RETRY_MINUTES: "5",
      SCANS_MAX_ACTIVE_PER_USER: "2",
      QUEUE_PREFIX: "",
    });
    expect(config).toMatchObject({
      intervalMs: 30_000,
      batchSize: 25,
      retryDelayMs: 300_000,
      queuePrefix: "header-auditor",
      limits: { maxActivePerUser: 2 },
    });
  });

  it("requires DATABASE_URL and REDIS_URL", () => {
    const problems = problemsOf({});
    expect(problems.some((p) => p.startsWith("DATABASE_URL"))).toBe(true);
    expect(problems.some((p) => p.startsWith("REDIS_URL"))).toBe(true);
  });

  it.each([
    ["SCHEDULER_INTERVAL_SECONDS", "1"],
    ["SCHEDULER_INTERVAL_SECONDS", "1.5"],
    ["SCHEDULER_BATCH_SIZE", "0"],
    ["SCHEDULER_MAX_BATCHES_PER_TICK", "1000"],
    ["SCHEDULER_RETRY_MINUTES", "-1"],
    ["QUEUE_PREFIX", "has spaces"],
    ["LOG_LEVEL", "loud"],
  ])("rejects %s=%s", (key, value) => {
    expect(problemsOf({ ...BASE, [key]: value }).some((p) => p.startsWith(key))).toBe(true);
  });

  it("never echoes connection strings in errors", () => {
    const problems = problemsOf({
      DATABASE_URL: `mysql://root:${SECRET}@127.0.0.1/db`,
      REDIS_URL: `http://:${SECRET}@127.0.0.1`,
    });
    expect(problems).toHaveLength(2);
    expect(problems.join("\n")).not.toContain(SECRET);
  });
});

describe(".env.example", () => {
  it("documents every scheduler variable with values that load to the defaults", () => {
    // Fixed repo file, not user input.
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const text = readFileSync(new URL("../../../.env.example", import.meta.url), "utf8");
    const env = Object.fromEntries(
      text
        .split("\n")
        .filter((line) => /^[A-Z_]+=/.test(line))
        .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
    );
    for (const key of SCHEDULER_CONFIG_KEYS) expect(env).toHaveProperty(key);
    const { DATABASE_URL = "", REDIS_URL = "" } = env;
    expect(loadSchedulerConfig({ ...env, NODE_ENV: "development" })).toEqual(
      loadSchedulerConfig({ DATABASE_URL, REDIS_URL }),
    );
  });
});
