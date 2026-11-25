/**
 * REDIS_URL parsing into ioredis connection options.
 *
 * Validated up front so a typo stops the process at startup with a message
 * that never includes the password, instead of ioredis retrying a bad host
 * forever in the background.
 */

export class RedisUrlError extends Error {
  override readonly name = "RedisUrlError";
}

/**
 * - `producer` (the API): fail fast. If Redis is down, `POST /scans` should
 *   get an error within a second, not queue the command in memory and hang
 *   the HTTP request.
 * - `consumer` (the worker): BullMQ requires `maxRetriesPerRequest: null`
 *   for blocking commands, and a worker should keep reconnecting.
 */
export type RedisRole = "producer" | "consumer";

/** Structural subset of ioredis `RedisOptions`. */
export interface RedisConnectionOptions {
  readonly host: string;
  readonly port: number;
  readonly db: number;
  readonly username?: string;
  readonly password?: string;
  /** Present for rediss:// URLs; certificate checks stay on. */
  readonly tls?: { readonly servername?: string };
  readonly maxRetriesPerRequest: number | null;
  readonly enableOfflineQueue: boolean;
  readonly connectTimeout: number;
}

interface ParsedRedisUrl {
  readonly host: string;
  readonly port: number;
  readonly db: number;
  readonly username: string | undefined;
  readonly password: string | undefined;
  readonly tls: boolean;
}

const DEFAULT_PORT = 6379;
/** Redis' default `databases 16`. */
const MAX_DB = 15;

function decode(component: string, what: string): string | undefined {
  if (component === "") return undefined;
  try {
    return decodeURIComponent(component);
  } catch {
    throw new RedisUrlError(`REDIS_URL ${what} is not valid percent-encoding`);
  }
}

export function parseRedisUrl(raw: string | undefined): ParsedRedisUrl {
  if (raw === undefined || raw.trim() === "") throw new RedisUrlError("REDIS_URL is not set");
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    // Never echo the value: it usually contains the password.
    throw new RedisUrlError("REDIS_URL is not a valid URL");
  }
  if (url.protocol !== "redis:" && url.protocol !== "rediss:") {
    throw new RedisUrlError("REDIS_URL must start with redis:// or rediss://");
  }
  if (url.hostname === "") throw new RedisUrlError("REDIS_URL must include a host");
  if (url.search !== "" || url.hash !== "") {
    throw new RedisUrlError("REDIS_URL must not have a query string or fragment");
  }
  let db = 0;
  const path = url.pathname.replace(/^\//, "");
  if (path !== "") {
    if (!/^\d{1,2}$/.test(path) || Number(path) > MAX_DB) {
      throw new RedisUrlError(`REDIS_URL database must be 0-${String(MAX_DB)}`);
    }
    db = Number(path);
  }
  return {
    host: url.hostname.replace(/^\[(.*)\]$/, "$1"),
    port: url.port === "" ? DEFAULT_PORT : Number(url.port),
    db,
    username: decode(url.username, "username"),
    password: decode(url.password, "password"),
    tls: url.protocol === "rediss:",
  };
}

export function redisConnectionOptions(
  raw: string | undefined,
  role: RedisRole,
): RedisConnectionOptions {
  const parsed = parseRedisUrl(raw);
  return {
    host: parsed.host,
    port: parsed.port,
    db: parsed.db,
    ...(parsed.username === undefined ? {} : { username: parsed.username }),
    ...(parsed.password === undefined ? {} : { password: parsed.password }),
    ...(parsed.tls ? { tls: { servername: parsed.host } } : {}),
    maxRetriesPerRequest: role === "consumer" ? null : 1,
    enableOfflineQueue: role === "consumer",
    connectTimeout: 5_000,
  };
}

/** For logs: `redis://:***@127.0.0.1:6379/0`. Unparseable input becomes a placeholder. */
export function redactRedisUrl(raw: string): string {
  try {
    const url = new URL(raw);
    if (url.password !== "") url.password = "***";
    return url.toString();
  } catch {
    return "<invalid REDIS_URL>";
  }
}
