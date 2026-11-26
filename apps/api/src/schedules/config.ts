/**
 * Scheduler process configuration, validated once at startup.
 *
 * Like the API and worker configs, problems name the variable but never echo
 * its value (DATABASE_URL and REDIS_URL hold passwords). The two SCANS_*
 * limits have the same names and defaults as the API's, so one .env drives
 * both and scheduled scans obey exactly the limits manual ones do.
 */
import {
  DEFAULT_QUEUE_PREFIX,
  isQueuePrefix,
  parseRedisUrl,
  RedisUrlError,
} from "@header-auditor/queue";
import { z } from "zod";

import { type Env, LOG_LEVELS, type LogLevel, NODE_ENVS, type NodeEnv } from "../config.js";
import type { CreateScanLimits } from "../scans/store.js";

export class SchedulerConfigError extends Error {
  override readonly name = "SchedulerConfigError";

  constructor(readonly problems: readonly string[]) {
    super(`Invalid scheduler configuration:\n  - ${problems.join("\n  - ")}`);
  }
}

const integer = (min: number, max: number) =>
  z
    .string()
    .trim()
    .regex(/^\d+$/, "must be a whole number")
    .transform(Number)
    .pipe(z.number().int().min(min).max(max));

const redisUrl = z.string().superRefine((value, ctx) => {
  try {
    parseRedisUrl(value);
  } catch (error) {
    ctx.addIssue({
      code: "custom",
      message: error instanceof RedisUrlError ? error.message : "is invalid",
    });
  }
});

const databaseUrl = z
  .string()
  .refine((value) => /^postgres(ql)?:\/\//.test(value), "must start with postgres://");

const envSchema = z.object({
  NODE_ENV: z.enum(NODE_ENVS).default("development"),
  LOG_LEVEL: z.enum(LOG_LEVELS).default("info"),
  DATABASE_URL: databaseUrl,
  REDIS_URL: redisUrl,
  QUEUE_PREFIX: z
    .string()
    .refine(isQueuePrefix, "must be 1-64 letters, digits, '.', '_' or '-'")
    .default(DEFAULT_QUEUE_PREFIX),
  // How often to look for due sites. Schedules are daily/weekly, so a minute is plenty.
  SCHEDULER_INTERVAL_SECONDS: integer(5, 3_600).default(60),
  SCHEDULER_BATCH_SIZE: integer(1, 1_000).default(100),
  SCHEDULER_MAX_BATCHES_PER_TICK: integer(1, 100).default(10),
  // Retry delay when a run couldn't be queued (owner at their limit, Redis down).
  SCHEDULER_RETRY_MINUTES: integer(1, 360).default(15),
  SCHEDULER_SHUTDOWN_TIMEOUT_MS: integer(1_000, 300_000).default(30_000),
  SCANS_MAX_ACTIVE_PER_USER: integer(1, 100).default(5),
  SCANS_ACTIVE_WINDOW_MINUTES: integer(1, 1_440).default(15),
});

export const SCHEDULER_CONFIG_KEYS = Object.keys(envSchema.shape) as readonly string[];

export interface SchedulerConfig {
  readonly nodeEnv: NodeEnv;
  readonly logLevel: LogLevel;
  readonly databaseUrl: string;
  readonly redisUrl: string;
  readonly queuePrefix: string;
  readonly intervalMs: number;
  readonly batchSize: number;
  readonly maxBatchesPerTick: number;
  readonly retryDelayMs: number;
  readonly shutdownTimeoutMs: number;
  readonly limits: CreateScanLimits;
}

/** Known keys only, and empty strings mean unset (`KEY=` in a .env uses the default). */
function pickKnownKeys(env: Env): Record<string, string> {
  const known = new Set(SCHEDULER_CONFIG_KEYS);
  return Object.fromEntries(
    Object.entries(env).filter(
      (entry): entry is [string, string] =>
        known.has(entry[0]) && entry[1] !== undefined && entry[1].trim() !== "",
    ),
  );
}

export function loadSchedulerConfig(env: Env = process.env): SchedulerConfig {
  const result = envSchema.safeParse(pickKnownKeys(env));
  if (!result.success) {
    throw new SchedulerConfigError(
      result.error.issues.map((issue) => {
        const key = issue.path.map(String).join(".") || "<root>";
        return `${key}: ${issue.message}`;
      }),
    );
  }
  const parsed = result.data;
  return Object.freeze({
    nodeEnv: parsed.NODE_ENV,
    logLevel: parsed.LOG_LEVEL,
    databaseUrl: parsed.DATABASE_URL,
    redisUrl: parsed.REDIS_URL,
    queuePrefix: parsed.QUEUE_PREFIX,
    intervalMs: parsed.SCHEDULER_INTERVAL_SECONDS * 1_000,
    batchSize: parsed.SCHEDULER_BATCH_SIZE,
    maxBatchesPerTick: parsed.SCHEDULER_MAX_BATCHES_PER_TICK,
    retryDelayMs: parsed.SCHEDULER_RETRY_MINUTES * 60_000,
    shutdownTimeoutMs: parsed.SCHEDULER_SHUTDOWN_TIMEOUT_MS,
    limits: Object.freeze({
      maxActivePerUser: parsed.SCANS_MAX_ACTIVE_PER_USER,
      activeWindowMs: parsed.SCANS_ACTIVE_WINDOW_MINUTES * 60_000,
    }),
  });
}
