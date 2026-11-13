import { makeFinding, Status, type Finding } from "../finding.js";
import type { HeaderMap } from "../headers.js";

export const COOKIES_CHECK = "Cookie flags";
const WEIGHT = 10;
const PENALTY_PER_COOKIE = 3;

export interface ParsedSetCookie {
  /** Cookie name as sent (may be empty for a malformed header). */
  readonly name: string;
  /** Lowercased attribute names, e.g. "secure", "httponly", "samesite". */
  readonly attributes: ReadonlySet<string>;
}

/**
 * Minimal RFC 6265 §5.2 split of one Set-Cookie line: the name-value pair is
 * everything before the first ";", and each attribute name is trimmed and
 * compared case-insensitively (so `SameSite = Lax` counts). Attribute values
 * are not needed for the flag checks, so they are not kept.
 */
export function parseSetCookie(line: string): ParsedSetCookie {
  const [pair = "", ...rawAttributes] = line.split(";");
  const name = (pair.split("=", 1)[0] ?? "").trim();
  const attributes = new Set(
    rawAttributes.map((a) => (a.split("=", 1)[0] ?? "").trim().toLowerCase()),
  );
  return { name, attributes };
}

export interface CookieOptions {
  /** `Secure` is only required when the response came over HTTPS. */
  isHttps?: boolean;
}

/** Names of the protective flags a cookie lacks, in a stable order. */
export function missingCookieFlags(
  cookie: ParsedSetCookie,
  { isHttps = true }: CookieOptions = {},
): string[] {
  const missing: string[] = [];
  if (isHttps && !cookie.attributes.has("secure")) missing.push("Secure");
  if (!cookie.attributes.has("httponly")) missing.push("HttpOnly");
  if (!cookie.attributes.has("samesite")) missing.push("SameSite");
  return missing;
}

export function checkCookies(headers: HeaderMap, options: CookieOptions = {}): Finding {
  const check = COOKIES_CHECK;
  const lines = headers.getAll("Set-Cookie");
  if (lines.length === 0) {
    return makeFinding({ check, status: Status.Info, detail: "No cookies set." });
  }

  const issues: string[] = [];
  for (const line of lines) {
    const cookie = parseSetCookie(line);
    const missing = missingCookieFlags(cookie, options);
    if (missing.length > 0) issues.push(`${cookie.name} missing ${missing.join("/")}`);
  }

  if (issues.length === 0) {
    return makeFinding({
      check,
      status: Status.Pass,
      detail: `All ${String(lines.length)} cookie(s) have Secure/HttpOnly/SameSite.`,
      weight: WEIGHT,
      score: WEIGHT,
    });
  }
  return makeFinding({
    check,
    status: Status.Warn,
    detail: `${issues.join("; ")}.`,
    weight: WEIGHT,
    score: Math.max(0, WEIGHT - PENALTY_PER_COOKIE * issues.length),
    recommendation: "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies.",
  });
}
