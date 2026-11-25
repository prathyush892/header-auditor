/**
 * JSON logging with pino, redacting anything that looks like a credential.
 * Scan logs carry ids, never URLs with userinfo or connection strings.
 */
import { pino, type Logger } from "pino";

import type { LogLevel } from "./config.js";

export const REDACT_PATHS: readonly string[] = [
  "*.password",
  "*.token",
  "*.secret",
  "*.databaseUrl",
  "*.redisUrl",
  "*.connection",
];

export function createLogger(level: LogLevel, destination?: NodeJS.WritableStream): Logger {
  const options = {
    level,
    base: { service: "worker" },
    redact: { paths: [...REDACT_PATHS], censor: "[REDACTED]" },
  };
  return destination === undefined ? pino(options) : pino(options, destination);
}
