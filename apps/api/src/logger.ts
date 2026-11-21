/**
 * Structured (JSON) logging via Fastify's built-in pino logger.
 *
 * Every line carries the request id, so one failed request can be followed
 * from "incoming request" to the stack trace. Credentials never reach the log:
 * auth/cookie headers are redacted and query strings are dropped from URLs
 * (they will carry tokens such as password-reset links).
 */
import { randomUUID } from "node:crypto";
import type { IncomingMessage } from "node:http";

import type { FastifyServerOptions } from "fastify";

import type { ApiConfig } from "./config.js";

export const REDACTED = "[REDACTED]";

/** pino redact paths. `*.password` etc. cover objects logged by route code. */
export const REDACT_PATHS: readonly string[] = [
  "req.headers.authorization",
  "req.headers.cookie",
  'req.headers["x-api-key"]',
  "req.headers['proxy-authorization']",
  'res.headers["set-cookie"]',
  "*.password",
  "*.passwordHash",
  "*.token",
  "*.secret",
];

export const REQUEST_ID_HEADER = "x-request-id";
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/;

/** Removes the query string and fragment so tokens in URLs aren't logged. */
export function stripQuery(url: string | undefined): string {
  if (url === undefined) return "";
  const end = url.search(/[?#]/);
  return end === -1 ? url : url.slice(0, end);
}

/**
 * Reuses a caller-supplied X-Request-Id (so ids can be correlated across a
 * proxy and the API) only if it is short and log-safe; otherwise a new UUID.
 * Without this check a client could inject newlines or megabytes into logs.
 */
export function generateRequestId(request: IncomingMessage): string {
  const header = request.headers["x-request-id"];
  const candidate = Array.isArray(header) ? header[0] : header;
  if (candidate !== undefined && REQUEST_ID_PATTERN.test(candidate)) return candidate;
  return randomUUID();
}

interface SerializableRequest {
  readonly method?: string;
  readonly url?: string;
  readonly ip?: string;
}

export function serializeRequest(request: SerializableRequest): Record<string, string | undefined> {
  return { method: request.method, url: stripQuery(request.url), remoteAddress: request.ip };
}

export interface LoggerOverrides {
  /** Where log lines go; defaults to stdout. Tests pass a stream to inspect output. */
  readonly stream?: NodeJS.WritableStream;
}

export function loggerOptions(
  config: Pick<ApiConfig, "logLevel">,
  overrides: LoggerOverrides = {},
): Exclude<FastifyServerOptions["logger"], boolean | undefined> {
  return {
    level: config.logLevel,
    base: { service: "api" },
    timestamp: () => `,"time":"${new Date().toISOString()}"`,
    redact: { paths: [...REDACT_PATHS], censor: REDACTED },
    serializers: { req: serializeRequest },
    ...(overrides.stream === undefined ? {} : { stream: overrides.stream }),
  };
}
