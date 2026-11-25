/**
 * Worker configuration from the environment, validated once at startup.
 *
 * As in the API, a bad value stops the process with a message that names the
 * variable but never echoes its value (DATABASE_URL and REDIS_URL hold
 * passwords).
 */
import { MAX_TIMEOUT_MS } from "@header-auditor/core";
import {
  DEFAULT_QUEUE_PREFIX,
  isQueuePrefix,
  parseRedisUrl,
  RedisUrlError,
} from "@header-auditor/queue";
import { z } from "zod";

export class WorkerConfigError extends Error {
  override readonly name = "WorkerConfigError";

  constructor(readonly problems: readonly string[]) {
    super(`Invalid worker configuration:\n  - ${problems.join("\n  - ")}`);
  }
}

export const LOG_LEVELS = ["fatal", "error", "warn", "info", "debug", "trace", "silent"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

const booleanFlag = z
  .string()
  .trim()
  .toLowerCase()
  .pipe(z.enum(["true", "false", "1", "0"]))
  .transform((value) => value === "true" || value === "1");

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
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  LOG_LEVEL: z.enum(LOG_LEVELS).default("info"),
  DATABASE_URL: databaseUrl,
  REDIS_URL: redisUrl,
  QUEUE_PREFIX: z
    .string()
    .refine(isQueuePrefix, "must be 1-64 letters, digits, '.', '_' or '-'")
    .default(DEFAULT_QUEUE_PREFIX),
  // Scans run in parallel per process; each holds a few sockets to one target.
  WORKER_CONCURRENCY: integer(1, 50).default(4),
  // Budget for each network phase of a scan (page fetch, then TLS/DNS/well-known).
  WORKER_SCAN_TIMEOUT_MS: integer(1_000, MAX_TIMEOUT_MS).default(30_000),
  // A RUNNING scan older than this is assumed orphaned and may be re-claimed.
  WORKER_STALE_AFTER_SECONDS: integer(60, 3_600).default(300),
  WORKER_SHUTDOWN_TIMEOUT_MS: integer(1_000, 300_000).default(60_000),
  // Scan loopback/private addresses. Dev/e2e only; refused in production.
  WORKER_ALLOW_PRIVATE_TARGETS: booleanFlag.default(false),
});

type ParsedEnv = z.infer<typeof envSchema>;

export const WORKER_CONFIG_KEYS = Object.keys(envSchema.shape) as readonly string[];

export interface WorkerConfig {
  readonly nodeEnv: ParsedEnv["NODE_ENV"];
  readonly logLevel: LogLevel;
  readonly databaseUrl: string;
  readonly redisUrl: string;
  readonly queuePrefix: string;
  readonly concurrency: number;
  readonly scanTimeoutMs: number;
  readonly staleAfterMs: number;
  readonly shutdownTimeoutMs: number;
  readonly allowPrivateTargets: boolean;
}

/** Phases of one scan that run one after the other, each with its own timeout. */
export const SCAN_PHASES = 2;

function crossFieldProblems(env: ParsedEnv): string[] {
  const problems: string[] = [];
  if (env.NODE_ENV === "production" && env.WORKER_ALLOW_PRIVATE_TARGETS) {
    problems.push("WORKER_ALLOW_PRIVATE_TARGETS: must be false in production");
  }
  // A healthy scan must never look stale, or a second worker would re-run it.
  if (env.WORKER_STALE_AFTER_SECONDS * 1_000 <= SCAN_PHASES * env.WORKER_SCAN_TIMEOUT_MS) {
    problems.push(
      `WORKER_STALE_AFTER_SECONDS: must exceed ${String(SCAN_PHASES)} x WORKER_SCAN_TIMEOUT_MS`,
    );
  }
  return problems;
}

export type Env = Readonly<Record<string, string | undefined>>;

export function loadWorkerConfig(env: Env = process.env): WorkerConfig {
  const known = new Set(WORKER_CONFIG_KEYS);
  const picked = Object.fromEntries(
    Object.entries(env).filter(
      (entry): entry is [string, string] =>
        known.has(entry[0]) && entry[1] !== undefined && entry[1].trim() !== "",
    ),
  );
  const result = envSchema.safeParse(picked);
  if (!result.success) {
    throw new WorkerConfigError(
      result.error.issues.map((issue) => {
        const key = issue.path.map(String).join(".") || "<root>";
        return `${key}: ${issue.message}`;
      }),
    );
  }
  const parsed = result.data;
  const problems = crossFieldProblems(parsed);
  if (problems.length > 0) throw new WorkerConfigError(problems);
  return Object.freeze({
    nodeEnv: parsed.NODE_ENV,
    logLevel: parsed.LOG_LEVEL,
    databaseUrl: parsed.DATABASE_URL,
    redisUrl: parsed.REDIS_URL,
    queuePrefix: parsed.QUEUE_PREFIX,
    concurrency: parsed.WORKER_CONCURRENCY,
    scanTimeoutMs: parsed.WORKER_SCAN_TIMEOUT_MS,
    staleAfterMs: parsed.WORKER_STALE_AFTER_SECONDS * 1_000,
    shutdownTimeoutMs: parsed.WORKER_SHUTDOWN_TIMEOUT_MS,
    allowPrivateTargets: parsed.WORKER_ALLOW_PRIVATE_TARGETS,
  });
}
