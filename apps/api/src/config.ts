/**
 * API configuration, read from the environment once at startup and validated
 * with zod.
 *
 * A bad value (typo'd port, unknown log level) must stop the process before it
 * binds a socket, with a message that names the variable but never echoes its
 * value: some of these variables will hold secrets in later steps.
 */
import { isIP } from "node:net";

import { z } from "zod";

export class ConfigError extends Error {
  override readonly name = "ConfigError";

  constructor(readonly problems: readonly string[]) {
    super(`Invalid API configuration:\n  - ${problems.join("\n  - ")}`);
  }
}

export const LOG_LEVELS = ["fatal", "error", "warn", "info", "debug", "trace", "silent"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

export const NODE_ENVS = ["development", "test", "production"] as const;
export type NodeEnv = (typeof NODE_ENVS)[number];

const KIB = 1024;
const MIB = 1024 * KIB;

/** "true"/"false"/"1"/"0" (any case). Anything else is an error, not `false`. */
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

const LABEL_CHARS = /^[A-Za-z0-9-]+$/;

/** RFC 1123 label: 1-63 letters, digits or hyphens, not starting/ending with "-". */
function isHostLabel(label: string): boolean {
  return (
    label.length >= 1 &&
    label.length <= 63 &&
    LABEL_CHARS.test(label) &&
    !label.startsWith("-") &&
    !label.endsWith("-")
  );
}

/** Hostname (RFC 1123 labels) or IP literal; IPv6 may be wrapped in brackets. */
export function isBindableHost(value: string): boolean {
  const unbracketed = value.replace(/^\[(.*)\]$/, "$1");
  if (isIP(unbracketed) !== 0) return true;
  if (value.length > 253) return false;
  return value.split(".").every(isHostLabel);
}

/**
 * Host to bind. Deliberately strict: no scheme, port, path or whitespace, which
 * catches "http://0.0.0.0:3001"-style mistakes.
 */
const host = z
  .string()
  .trim()
  .refine(isBindableHost, "must be a hostname or IP address (no scheme or port)")
  .transform((value) => value.replace(/^\[(.*)\]$/, "$1"));

const envSchema = z.object({
  NODE_ENV: z.enum(NODE_ENVS).default("development"),
  LOG_LEVEL: z.enum(LOG_LEVELS).default("info"),
  // Loopback by default: exposing the API is an explicit decision (containers set 0.0.0.0).
  API_HOST: host.default("127.0.0.1"),
  API_PORT: integer(0, 65_535).default(3001),
  API_TRUST_PROXY: booleanFlag.default(false),
  API_BODY_LIMIT_BYTES: integer(KIB, 10 * MIB).default(MIB),
  API_REQUEST_TIMEOUT_MS: integer(1_000, 120_000).default(30_000),
  API_SHUTDOWN_TIMEOUT_MS: integer(1_000, 60_000).default(10_000),
  API_READINESS_TIMEOUT_MS: integer(100, 30_000).default(2_000),
});

/** Environment variable names the API reads; nothing else is looked at. */
export const CONFIG_KEYS = Object.keys(
  envSchema.shape,
) as readonly (keyof typeof envSchema.shape)[];

export interface ApiConfig {
  readonly nodeEnv: NodeEnv;
  readonly logLevel: LogLevel;
  readonly host: string;
  readonly port: number;
  readonly trustProxy: boolean;
  readonly bodyLimitBytes: number;
  readonly requestTimeoutMs: number;
  readonly shutdownTimeoutMs: number;
  readonly readinessTimeoutMs: number;
}

export type Env = Readonly<Record<string, string | undefined>>;

/**
 * Copies only the keys we know about, treating empty strings as unset so that
 * `API_PORT=` in a .env file means "use the default" rather than "port 0".
 */
function pickKnownKeys(env: Env): Record<string, string> {
  const known = new Set<string>(CONFIG_KEYS);
  return Object.fromEntries(
    Object.entries(env).filter(
      (entry): entry is [string, string] =>
        known.has(entry[0]) && entry[1] !== undefined && entry[1].trim() !== "",
    ),
  );
}

function describeIssue(issue: z.core.$ZodIssue): string {
  const key = issue.path.map(String).join(".") || "<root>";
  // Zod's own messages for enums list the allowed options, never the input.
  return `${key}: ${issue.message}`;
}

/** Validates the environment and returns a frozen, typed config. Throws ConfigError. */
export function loadConfig(env: Env = process.env): ApiConfig {
  const result = envSchema.safeParse(pickKnownKeys(env));
  if (!result.success) {
    throw new ConfigError(result.error.issues.map(describeIssue));
  }
  const parsed = result.data;
  return Object.freeze({
    nodeEnv: parsed.NODE_ENV,
    logLevel: parsed.LOG_LEVEL,
    host: parsed.API_HOST,
    port: parsed.API_PORT,
    trustProxy: parsed.API_TRUST_PROXY,
    bodyLimitBytes: parsed.API_BODY_LIMIT_BYTES,
    requestTimeoutMs: parsed.API_REQUEST_TIMEOUT_MS,
    shutdownTimeoutMs: parsed.API_SHUTDOWN_TIMEOUT_MS,
    readinessTimeoutMs: parsed.API_READINESS_TIMEOUT_MS,
  });
}
