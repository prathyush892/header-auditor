/**
 * Session and CSRF tokens.
 *
 * - The session token is 256 bits from the OS CSPRNG, sent to the browser in
 *   an httpOnly cookie. The database stores only SHA-256(token): looking a
 *   session up needs the token, and a dump of the table can't be replayed.
 *   (A fast hash is fine here, unlike for passwords: the input is random and
 *   256 bits long, so there is nothing to brute-force.)
 * - The CSRF token is HMAC-SHA256(key = session token, "csrf:v1"). JavaScript
 *   on our dashboard gets it from the API and echoes it in a header; a page on
 *   another origin can make the browser *send* the cookie but can't *read*
 *   the token, and can't compute it without the httpOnly session token.
 *   Deriving it means no extra server secret and no extra database column.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const SESSION_TOKEN_BYTES = 32;
/** base64url of 32 bytes, no padding. */
const SESSION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const CSRF_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const CSRF_CONTEXT = "csrf:v1";

export function generateSessionToken(): string {
  return randomBytes(SESSION_TOKEN_BYTES).toString("base64url");
}

/** Cheap shape check before touching the database with attacker-supplied cookies. */
export function isWellFormedSessionToken(value: unknown): value is string {
  return typeof value === "string" && SESSION_TOKEN_PATTERN.test(value);
}

/** Lower-case hex SHA-256: the only form of the token that is ever stored. */
export function hashSessionToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function deriveCsrfToken(sessionToken: string): string {
  return createHmac("sha256", sessionToken).update(CSRF_CONTEXT).digest("base64url");
}

/** Constant-time comparison so response timing doesn't leak how many characters matched. */
export function verifyCsrfToken(sessionToken: string, presented: unknown): boolean {
  if (typeof presented !== "string" || !CSRF_TOKEN_PATTERN.test(presented)) return false;
  const expected = Buffer.from(deriveCsrfToken(sessionToken), "utf8");
  const actual = Buffer.from(presented, "utf8");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
