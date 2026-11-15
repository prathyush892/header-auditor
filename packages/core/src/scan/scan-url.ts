/**
 * `scanUrl()`: the network edge of the engine. Fetches a URL with undici,
 * follows redirects hop by hop under the SSRF policy, then grades the final
 * response's headers with the pure checks in `report.ts`.
 *
 * Every hop is re-validated (scheme, credentials, IP literal, DNS answer),
 * because a redirect is just another user-controlled URL: a public page that
 * answers `302 Location: http://169.254.169.254/` must not get through.
 */
import { Agent, request, type Dispatcher } from "undici";
import { HeaderMap, type HeaderInput } from "../headers.js";
import { buildReport, runAll, type Report } from "../report.js";
import {
  isAddressAllowed,
  normalizeAddress,
  parseAllowList,
  type AddressPolicy,
} from "./address.js";
import { ScanError, type ScanErrorCode } from "./errors.js";
import {
  createGuardedLookup,
  systemResolver,
  type LookupOutcome,
  type Resolver,
} from "./lookup.js";

/** Only these schemes are ever fetched, on the first hop or after a redirect. */
export const ALLOWED_SCHEMES: readonly string[] = ["http:", "https:"];
export const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

export const DEFAULT_TIMEOUT_MS = 10_000;
export const MAX_TIMEOUT_MS = 120_000;
export const DEFAULT_MAX_REDIRECTS = 5;
export const MAX_REDIRECTS_LIMIT = 20;
export const MAX_URL_LENGTH = 2048;
export const DEFAULT_USER_AGENT = "header-auditor-core (+security header check)";

export interface ScanOptions {
  /** Total time budget for the whole scan, every hop included. Default 10 s. */
  timeoutMs?: number;
  /** Follow 3xx redirects (default true). False grades the first response. */
  followRedirects?: boolean;
  /** Redirects to follow before failing with TOO_MANY_REDIRECTS. Default 5. */
  maxRedirects?: number;
  /** Allow loopback/private/reserved targets. Off by default; for local dev only. */
  allowPrivate?: boolean;
  /** Specific IPs or CIDRs reachable even when `allowPrivate` is false. */
  allowAddresses?: readonly string[];
  /** Hostname resolver; defaults to the OS resolver. Inject fixtures in tests. */
  resolver?: Resolver;
  userAgent?: string;
  /**
   * PEM CA certificate(s) to trust for https targets *instead of* the system
   * roots, for a private PKI or tests. Certificate errors are never ignored.
   */
  ca?: string | readonly string[];
  /** Cancels the scan (e.g. the API request was aborted). */
  signal?: AbortSignal;
}

export interface RedirectHop {
  readonly url: string;
  readonly statusCode: number;
  /** The absolute URL the Location header pointed to. */
  readonly location: string;
}

export interface ScanResult {
  readonly report: Report;
  /** Every redirect that was followed, in order; empty when there were none. */
  readonly redirects: readonly RedirectHop[];
}

interface ResolvedOptions {
  timeoutMs: number;
  followRedirects: boolean;
  maxRedirects: number;
  policy: AddressPolicy;
  resolver: Resolver;
  userAgent: string;
  ca: string[] | undefined;
  signal: AbortSignal | undefined;
}

function invalidOption(message: string): ScanError {
  return new ScanError("INVALID_OPTIONS", message);
}

/** Validates the `ca` option: one or more PEM certificates, or undefined. */
export function normalizeCaOption(
  ca: string | readonly string[] | undefined,
): string[] | undefined {
  if (ca === undefined) return undefined;
  const list: unknown[] = typeof ca === "string" ? [ca] : [...ca];
  const valid = list.every(
    (c): c is string => typeof c === "string" && c.includes("-----BEGIN CERTIFICATE-----"),
  );
  if (list.length === 0 || !valid) {
    throw invalidOption("ca must be one or more PEM-encoded certificates");
  }
  return list;
}

function resolveOptions(options: ScanOptions): ResolvedOptions {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw invalidOption(`timeoutMs must be an integer between 1 and ${String(MAX_TIMEOUT_MS)}`);
  }
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  if (!Number.isInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > MAX_REDIRECTS_LIMIT) {
    throw invalidOption(
      `maxRedirects must be an integer between 0 and ${String(MAX_REDIRECTS_LIMIT)}`,
    );
  }
  const userAgent = options.userAgent ?? DEFAULT_USER_AGENT;
  if (userAgent.length === 0 || userAgent.length > 256 || /[\r\n\0]/.test(userAgent)) {
    throw invalidOption("userAgent must be 1-256 characters without CR, LF or NUL");
  }
  let allowList;
  try {
    allowList = parseAllowList(options.allowAddresses ?? []);
  } catch (err) {
    throw invalidOption(err instanceof Error ? err.message : String(err));
  }
  return {
    timeoutMs,
    followRedirects: options.followRedirects ?? true,
    maxRedirects,
    policy: { allowPrivate: options.allowPrivate ?? false, allowList },
    resolver: options.resolver ?? systemResolver,
    userAgent,
    ca: normalizeCaOption(options.ca),
    signal: options.signal,
  };
}

/**
 * Parses and vets a URL before any connection is made: absolute http(s) only,
 * no embedded credentials, and IP-literal hosts checked against the policy
 * (sockets skip `lookup` for IP literals, so the DNS guard can't catch them).
 */
export function validateTarget(raw: string, policy: AddressPolicy): URL {
  if (raw.length > MAX_URL_LENGTH) {
    throw new ScanError("INVALID_URL", `URL is longer than ${String(MAX_URL_LENGTH)} characters`);
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch (cause) {
    throw new ScanError("INVALID_URL", `Not an absolute URL: ${JSON.stringify(raw)}`, { cause });
  }
  if (!ALLOWED_SCHEMES.includes(url.protocol)) {
    throw new ScanError(
      "BLOCKED_SCHEME",
      `Scheme ${url.protocol} is not allowed (http/https only)`,
      {
        url: url.href,
      },
    );
  }
  if (url.username !== "" || url.password !== "") {
    throw new ScanError("INVALID_URL", "URLs with embedded credentials are not allowed", {
      url: `${url.protocol}//${url.host}${url.pathname}`,
    });
  }
  if (url.hostname === "") {
    throw new ScanError("INVALID_URL", "URL has no host", { url: url.href });
  }
  const literal = normalizeAddress(url.hostname);
  if (literal && !isAddressAllowed(literal.address, policy)) {
    throw new ScanError("BLOCKED_ADDRESS", `Address ${literal.address} is not allowed`, {
      url: url.href,
    });
  }
  url.hash = "";
  return url;
}

function errorCode(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : undefined;
}

const TIMEOUT_CODES = new Set([
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_BODY_TIMEOUT",
]);

/** Certificate verification failures (OpenSSL verify codes plus Node's hostname check). */
const CERT_ERROR_CODES = new Set([
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "CERT_UNTRUSTED",
  "CERT_REVOKED",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

/** True for handshake and certificate failures, which get the TLS_ERROR code. */
export function isTlsFailure(err: unknown): boolean {
  const code = errorCode(err) ?? "";
  return CERT_ERROR_CODES.has(code) || code.startsWith("ERR_SSL_");
}

/** Maps whatever undici/the socket threw into one ScanError with a stable code. */
function toScanError(
  err: unknown,
  url: string,
  outcome: LookupOutcome,
  deadline: AbortSignal,
  external: AbortSignal | undefined,
): ScanError {
  if (err instanceof ScanError) return err;
  const fail = (code: ScanErrorCode, message: string): ScanError =>
    new ScanError(code, message, { url, cause: err });
  if (outcome.blocked) {
    return fail(
      "BLOCKED_ADDRESS",
      `${outcome.blocked.hostname} resolves to ${outcome.blocked.address}, which is not allowed`,
    );
  }
  if (external?.aborted) return fail("ABORTED", "Scan was aborted");
  if (deadline.aborted || TIMEOUT_CODES.has(errorCode(err) ?? "")) {
    return fail("TIMEOUT", "Scan timed out");
  }
  if (outcome.dnsError !== undefined)
    return fail("DNS_FAILURE", `Could not resolve ${new URL(url).hostname}`);
  const detail = err instanceof Error ? err.message : String(err);
  if (isTlsFailure(err)) return fail("TLS_ERROR", `TLS error: ${detail}`);
  return fail("NETWORK", `Request failed: ${detail}`);
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

interface HopResponse {
  statusCode: number;
  headers: Dispatcher.ResponseData["headers"];
}

async function fetchOnce(
  url: URL,
  dispatcher: Dispatcher,
  signal: AbortSignal,
  userAgent: string,
): Promise<HopResponse> {
  const res = await request(url, {
    method: "GET",
    dispatcher,
    signal,
    headers: { "user-agent": userAgent, accept: "text/html,*/*;q=0.8" },
  });
  // Only headers are graded; drain (bounded) so the socket can be released.
  await res.body.dump({ limit: 64 * 1024 });
  return { statusCode: res.statusCode, headers: res.headers };
}

/**
 * Fetches `rawUrl` and grades the final response's security headers.
 *
 * @throws ScanError with a stable `code` for bad input, blocked targets,
 *   redirect problems, timeouts and network failures.
 */
export async function scanUrl(rawUrl: string, options: ScanOptions = {}): Promise<ScanResult> {
  const opts = resolveOptions(options);
  const deadline = AbortSignal.timeout(opts.timeoutMs);
  const signal = opts.signal ? AbortSignal.any([deadline, opts.signal]) : deadline;
  const outcome: LookupOutcome = {};
  const agent = new Agent({
    connect: {
      lookup: createGuardedLookup(opts.resolver, opts.policy, outcome),
      ...(opts.ca ? { ca: opts.ca } : {}),
    },
    connectTimeout: opts.timeoutMs,
    headersTimeout: opts.timeoutMs,
    bodyTimeout: opts.timeoutMs,
  });

  const redirects: RedirectHop[] = [];
  const visited = new Set<string>();
  let current = validateTarget(rawUrl, opts.policy);
  try {
    for (;;) {
      visited.add(current.href);
      delete outcome.blocked;
      delete outcome.dnsError;
      let res: HopResponse;
      try {
        res = await fetchOnce(current, agent, signal, opts.userAgent);
      } catch (err) {
        throw toScanError(err, current.href, outcome, deadline, opts.signal);
      }

      const location = firstHeader(res.headers.location);
      const isRedirect = REDIRECT_STATUSES.has(res.statusCode) && location !== undefined;
      if (!isRedirect || !opts.followRedirects) {
        const headers = new HeaderMap(res.headers as HeaderInput);
        const findings = runAll(headers, { isHttps: current.protocol === "https:" });
        const report = buildReport(current.href, res.statusCode, findings);
        return Object.freeze({ report, redirects: Object.freeze(redirects) });
      }

      if (redirects.length >= opts.maxRedirects) {
        throw new ScanError(
          "TOO_MANY_REDIRECTS",
          `Stopped after ${String(opts.maxRedirects)} redirects`,
          { url: current.href },
        );
      }
      let next: URL;
      try {
        next = new URL(location, current);
      } catch (cause) {
        throw new ScanError("INVALID_URL", "Redirect has an invalid Location header", {
          url: current.href,
          cause,
        });
      }
      const target = validateTarget(next.href, opts.policy);
      if (visited.has(target.href)) {
        throw new ScanError("REDIRECT_LOOP", `Redirect loop back to ${target.href}`, {
          url: current.href,
        });
      }
      redirects.push(
        Object.freeze({ url: current.href, statusCode: res.statusCode, location: target.href }),
      );
      current = target;
    }
  } finally {
    await agent.destroy();
  }
}
