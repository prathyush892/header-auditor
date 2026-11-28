/**
 * Names of the API's session cookie (see apps/api/src/auth/plugin.ts; the
 * contract test checks they match). The dashboard never reads the value, it
 * can't (httpOnly). Middleware only checks whether one is present.
 */
export const SESSION_COOKIE_NAMES: readonly string[] = ["__Host-ha_session", "ha_session"];

interface CookieReader {
  has(name: string): boolean;
}

/**
 * Presence, not validity: an expired or forged cookie passes this check. It
 * only saves a round trip for visitors who obviously aren't signed in; the
 * API decides who is signed in on every request.
 */
export function hasSessionCookie(cookies: CookieReader): boolean {
  return SESSION_COOKIE_NAMES.some((name) => cookies.has(name));
}
