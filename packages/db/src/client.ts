/**
 * PrismaClient factory.
 *
 * Prisma 7 talks to Postgres through a JavaScript driver adapter (node-postgres
 * here) instead of a bundled Rust query engine, so the connection pool is a
 * normal `pg` pool we size explicitly.
 */
import { PrismaPg } from "@prisma/adapter-pg";

import { parseDatabaseUrl } from "./config.js";
import { PrismaClient } from "./generated/prisma/client.js";

export interface CreateClientOptions {
  /** Connection string; defaults to process.env.DATABASE_URL. */
  databaseUrl?: string;
  /** Maximum pooled connections (1-100). Defaults to 10. */
  maxConnections?: number;
  /** Milliseconds to wait for a new connection before failing (default 5000). */
  connectionTimeoutMs?: number;
}

export const DEFAULT_MAX_CONNECTIONS = 10;
export const DEFAULT_CONNECTION_TIMEOUT_MS = 5_000;

function checkInteger(name: string, value: number, min: number, max: number): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RangeError(`${name} must be an integer in [${String(min)}, ${String(max)}]`);
  }
  return value;
}

export function createPrismaClient(options: CreateClientOptions = {}): PrismaClient {
  const url = parseDatabaseUrl(options.databaseUrl ?? process.env.DATABASE_URL);
  const max = checkInteger(
    "maxConnections",
    options.maxConnections ?? DEFAULT_MAX_CONNECTIONS,
    1,
    100,
  );
  const connectionTimeoutMillis = checkInteger(
    "connectionTimeoutMs",
    options.connectionTimeoutMs ?? DEFAULT_CONNECTION_TIMEOUT_MS,
    1,
    120_000,
  );
  const adapter = new PrismaPg({ connectionString: url.toString(), max, connectionTimeoutMillis });
  return new PrismaClient({ adapter });
}
