/**
 * Validation and normalisation for what a user can register as a site.
 *
 * A site is an *origin* (scheme + host + optional port): that is what the
 * scanner fetches, what the unique index `(owner_id, url)` compares, and what
 * domain-ownership verification (DNS TXT, roadmap step 17) applies to. So
 * every spelling of one origin must collapse to one string:
 *
 *   "Example.COM"  "https://example.com/"  "https://example.com.:443"
 *     -> "https://example.com"
 *
 * This is also the first, cheap SSRF filter: IP literals, `localhost` and
 * special-use names (.internal, .local, ...) are refused up front so users get
 * a clear 400 instead of a failed scan. It is not the real SSRF control: a
 * public name can still resolve to 10.0.0.1, so the scanner re-checks every
 * resolved address at connect time (packages/core `scanUrl`).
 */
import { isIP } from "node:net";

export const SITE_URL_MAX_LENGTH = 2_048;
export const HOSTNAME_MAX_LENGTH = 253;
const LABEL_MAX_LENGTH = 63;

/** IANA special-use and common private suffixes that never name a public site. */
export const RESERVED_SUFFIXES: readonly string[] = [
  "localhost",
  "local",
  "localdomain",
  "internal",
  "intranet",
  "lan",
  "home",
  "corp",
  "home.arpa",
  "invalid",
  "test",
  "example",
  "onion",
];

export interface SiteUrlOptions {
  /** Accept IP literals, localhost and single-label hosts (dev and e2e only). */
  readonly allowPrivateTargets?: boolean;
}

export type Normalized = { readonly ok: true; readonly value: string } | Invalid;
interface Invalid {
  readonly ok: false;
  readonly reason: string;
}

function invalid(reason: string): Invalid {
  return { ok: false, reason };
}

/** True for a dotted DNS name whose labels are LDH (letters, digits, hyphen). */
export function isDnsHostname(host: string): boolean {
  if (host.length === 0 || host.length > HOSTNAME_MAX_LENGTH) return false;
  const labels = host.split(".");
  return labels.every(
    (label) =>
      label.length > 0 &&
      label.length <= LABEL_MAX_LENGTH &&
      /^[a-z0-9-]+$/.test(label) &&
      !label.startsWith("-") &&
      !label.endsWith("-"),
  );
}

function isReservedName(host: string): boolean {
  return RESERVED_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

/** `URL.hostname` keeps IPv6 brackets; `isIP` wants them stripped. */
function unbracket(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/**
 * Checks a hostname that `URL` has already lower-cased and punycoded. Returns
 * a reason string when it isn't acceptable.
 */
function hostProblem(host: string, options: SiteUrlOptions): string | undefined {
  const allowPrivate = options.allowPrivateTargets === true;
  if (isIP(unbracket(host)) !== 0) {
    return allowPrivate ? undefined : "must use a domain name, not an IP address";
  }
  if (!isDnsHostname(host)) return "has an invalid hostname";
  if (allowPrivate) return undefined;
  if (!host.includes(".")) return "must use a fully qualified domain name";
  // An all-numeric last label is never a real TLD (and hints at IPv4 tricks).
  if (/^\d+$/.test(host.slice(host.lastIndexOf(".") + 1))) return "has an invalid hostname";
  if (isReservedName(host)) return "must be a public domain name";
  return undefined;
}

function parse(input: string): URL | undefined {
  // "example.com" is what people type; treat a missing scheme as https.
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
  try {
    return new URL(withScheme);
  } catch {
    return undefined;
  }
}

/** Normalises a user-supplied site URL to its origin, e.g. "https://example.com". */
export function normalizeSiteUrl(raw: string, options: SiteUrlOptions = {}): Normalized {
  const input = raw.trim();
  if (input.length === 0) return invalid("is required");
  if (input.length > SITE_URL_MAX_LENGTH) return invalid("is too long");
  // eslint-disable-next-line no-control-regex
  if (/[\u0000- \u007f]/.test(input))
    return invalid("must not contain spaces or control characters");
  const url = parse(input);
  if (url === undefined) return invalid("must be a valid URL");
  if (url.protocol !== "https:" && url.protocol !== "http:")
    return invalid("must use http or https");
  if (url.username !== "" || url.password !== "") return invalid("must not contain credentials");
  if (
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== "" ||
    input.endsWith("?") ||
    input.endsWith("#")
  ) {
    return invalid(
      "must be an origin without a path, query or fragment (e.g. https://example.com)",
    );
  }
  // One spelling per origin: drop the root-zone dot ("example.com.").
  const host = url.hostname.endsWith(".") ? url.hostname.slice(0, -1) : url.hostname;
  const problem = hostProblem(host, options);
  if (problem !== undefined) return invalid(problem);
  const port = url.port === "" ? "" : `:${url.port}`;
  return { ok: true, value: `${url.protocol}//${host}${port}` };
}

/**
 * Normalises a bare hostname for `firstPartyHosts` (no scheme, port or path).
 * Unicode names are converted to punycode so they compare equal to what the
 * scanner sees in fetched HTML.
 */
export function normalizeHostname(raw: string): Normalized {
  const input = raw.trim().toLowerCase();
  if (input.length === 0) return invalid("is required");
  if (input.length > HOSTNAME_MAX_LENGTH) return invalid("is too long");
  if (/[^\p{L}\p{N}.-]/u.test(input)) return invalid("must be a bare hostname");
  let host: string;
  try {
    host = new URL(`https://${input}`).hostname;
  } catch {
    return invalid("must be a bare hostname");
  }
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (isIP(host) !== 0 || !isDnsHostname(host) || !host.includes(".")) {
    return invalid("must be a fully qualified domain name");
  }
  return { ok: true, value: host };
}
