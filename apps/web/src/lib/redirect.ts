/**
 * `?next=` handling for the sign-in pages.
 *
 * After login we send the user back where they were going. Taken at face
 * value that's an open redirect: `/login?next=https://evil.example` would
 * bounce a freshly signed-in user to a phishing page that looks like a
 * continuation of ours. So `next` is only honoured when it resolves to a path
 * on our own origin, and never to the auth pages themselves (no loops).
 */
export const DEFAULT_AFTER_LOGIN = "/dashboard";
export const AUTH_PATHS: readonly string[] = ["/login", "/register"];
const NEXT_MAX_LENGTH = 2_048;
/** A placeholder origin: we only use it to see whether `next` stays on it. */
const PLACEHOLDER_ORIGIN = "http://placeholder.invalid";

export function safeNextPath(
  value: string | null | undefined,
  fallback: string = DEFAULT_AFTER_LOGIN,
): string {
  if (typeof value !== "string" || value === "" || value.length > NEXT_MAX_LENGTH) return fallback;
  // Must be a rooted path. `//host` and `/\host` are protocol-relative URLs
  // to browsers (backslash is treated as a slash), so both are rejected.
  if (!value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) {
    return fallback;
  }
  // Control characters (tabs and newlines are stripped by URL parsers) could
  // smuggle a `//` past the check above.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(value)) return fallback;
  let url: URL;
  try {
    url = new URL(value, PLACEHOLDER_ORIGIN);
  } catch {
    return fallback;
  }
  if (url.origin !== PLACEHOLDER_ORIGIN) return fallback;
  if (AUTH_PATHS.some((path) => url.pathname === path || url.pathname.startsWith(`${path}/`))) {
    return fallback;
  }
  return `${url.pathname}${url.search}${url.hash}`;
}

/** `/login?next=<current path>` for a page that needs a session. */
export function loginUrlFor(pathWithSearch: string): string {
  const next = safeNextPath(pathWithSearch, "");
  return next === "" || next === DEFAULT_AFTER_LOGIN
    ? "/login"
    : `/login?next=${encodeURIComponent(next)}`;
}
