/**
 * Build/start-time settings for the web app, read by next.config.ts.
 *
 * Only server-side values live here. Nothing in this file is prefixed
 * `NEXT_PUBLIC_`, so none of it is inlined into the browser bundle.
 */
export const DEFAULT_API_INTERNAL_URL = "http://127.0.0.1:3001";
export { API_PROXY_PREFIX } from "./api/client";

export class WebConfigError extends Error {
  override readonly name = "WebConfigError";
}

/**
 * Where Next.js forwards `/api/*`. Must be a bare http(s) origin: a path,
 * query or credentials in it would end up in every proxied request.
 */
export function parseApiInternalUrl(value: string | undefined): string {
  const raw = value === undefined || value.trim() === "" ? DEFAULT_API_INTERNAL_URL : value.trim();
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new WebConfigError(
      `API_INTERNAL_URL must be an absolute URL, got ${JSON.stringify(raw)}`,
    );
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new WebConfigError(`API_INTERNAL_URL must use http or https, got ${url.protocol}`);
  }
  if (url.username !== "" || url.password !== "") {
    throw new WebConfigError("API_INTERNAL_URL must not contain credentials");
  }
  if ((url.pathname !== "/" && url.pathname !== "") || url.search !== "" || url.hash !== "") {
    throw new WebConfigError(
      "API_INTERNAL_URL must be an origin only (no path, query or fragment)",
    );
  }
  return url.origin;
}

export interface HeaderEntry {
  readonly key: string;
  readonly value: string;
}

/**
 * Baseline response headers for every page. A nonce-based CSP comes with the
 * self-audit in roadmap step 24; until then these are the ones that can't
 * break anything. HSTS is left to the TLS-terminating proxy in production.
 */
export const SECURITY_HEADERS: readonly HeaderEntry[] = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-Frame-Options", value: "DENY" },
  {
    key: "Content-Security-Policy",
    value: "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'",
  },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  },
];
