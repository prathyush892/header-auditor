/**
 * `scanUrl()`: the network edge of the engine. Fetches a URL with undici,
 * follows redirects hop by hop under the SSRF policy, then grades the final
 * response's headers with the pure checks in `report.ts`.
 *
 * Every hop is re-validated (scheme, credentials, IP literal, DNS answer),
 * because a redirect is just another user-controlled URL: a public page that
 * answers `302 Location: http://169.254.169.254/` must not get through.
 */
import { TextDecoder } from "node:util";
import { Agent, request, type Dispatcher } from "undici";
import { buildContentReport, type ContentReport } from "../content/report.js";
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
/** HTML read from the final response for content checks. 1 MiB covers almost every page's markup. */
export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
export const MAX_BODY_BYTES_LIMIT = 10 * 1024 * 1024;
/** Bytes drained from responses whose body isn't inspected, so the socket can be reused. */
const DRAIN_LIMIT = 64 * 1024;

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
  /**
   * Bytes of the final response's HTML to read for content checks (mixed
   * content). Larger bodies are truncated, never buffered in full. 0 skips the
   * body. Default 1 MiB, max 10 MiB.
   */
  maxBodyBytes?: number;
  /**
   * Hosts besides the page's own (and its subdomains) that the Subresource
   * Integrity check treats as first-party, e.g. a CDN the site owner runs.
   */
  firstPartyHosts?: readonly string[];
}

export interface RedirectHop {
  readonly url: string;
  readonly statusCode: number;
  /** The absolute URL the Location header pointed to. */
  readonly location: string;
}

export interface ScanResult {
  /** Header checks, scored exactly like the Python CLI. */
  readonly report: Report;
  /** Every redirect that was followed, in order; empty when there were none. */
  readonly redirects: readonly RedirectHop[];
  /** Redirect-chain and mixed-content checks, scored separately. */
  readonly content: ContentReport;
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
  maxBodyBytes: number;
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
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes < 0 || maxBodyBytes > MAX_BODY_BYTES_LIMIT) {
    throw invalidOption(
      `maxBodyBytes must be an integer between 0 and ${String(MAX_BODY_BYTES_LIMIT)}`,
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
    maxBodyBytes,
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

const HTML_TYPES = new Set(["text/html", "application/xhtml+xml"]);

/** Media type and charset from a Content-Type value; parameters are case-insensitive. */
export function parseContentType(value: string | undefined): {
  mediaType: string;
  charset: string | undefined;
} {
  const [type = "", ...params] = (value ?? "").split(";");
  let charset: string | undefined;
  for (const param of params) {
    const eq = param.indexOf("=");
    if (eq === -1 || param.slice(0, eq).trim().toLowerCase() !== "charset") continue;
    charset = param
      .slice(eq + 1)
      .trim()
      .replace(/^"(.*)"$/, "$1");
  }
  return { mediaType: type.trim().toLowerCase(), charset };
}

/** True when a response should be read as HTML (a missing Content-Type is sniffed as HTML by browsers). */
export function isHtmlResponse(contentType: string | undefined): boolean {
  if (contentType === undefined) return true;
  return HTML_TYPES.has(parseContentType(contentType).mediaType);
}

function decoderFor(charset: string | undefined): TextDecoder {
  try {
    return new TextDecoder(charset ?? "utf-8");
  } catch {
    return new TextDecoder("utf-8"); // unknown label: fall back rather than fail the scan
  }
}

/**
 * Reads at most `limit` bytes of `body`, then stops pulling and lets the
 * caller discard the connection. Never buffers more than the limit, so a
 * hostile multi-gigabyte page can't exhaust memory.
 */
async function readBounded(
  body: Dispatcher.ResponseData["body"],
  limit: number,
): Promise<{ bytes: Buffer; truncated: boolean }> {
  const chunks: Buffer[] = [];
  let total = 0;
  let truncated = false;
  for await (const chunk of body as AsyncIterable<Buffer>) {
    const room = limit - total;
    if (chunk.length > room) {
      chunks.push(chunk.subarray(0, room));
      total += room;
      truncated = true;
      break;
    }
    chunks.push(chunk);
    total += chunk.length;
  }
  if (truncated) body.destroy();
  return { bytes: Buffer.concat(chunks, total), truncated };
}

/** Decides, per response, whether its body is read (and up to how many bytes). */
interface BodyPolicy {
  /** Sent as the Accept header. */
  accept: string;
  /** Max bytes to read; 0 never reads a body. */
  maxBytes: number;
  /** Whether a final (non-redirect) response's body should be read. */
  wants: (statusCode: number, contentType: string | undefined) => boolean;
}

interface HopResponse {
  statusCode: number;
  headers: Dispatcher.ResponseData["headers"];
  /** Decoded body when it was read, else undefined. */
  body: string | undefined;
  bodyBytes: number;
  bodyTruncated: boolean;
}

async function fetchOnce(
  url: URL,
  dispatcher: Dispatcher,
  signal: AbortSignal,
  userAgent: string,
  body: BodyPolicy,
): Promise<HopResponse> {
  const res = await request(url, {
    method: "GET",
    dispatcher,
    signal,
    headers: { "user-agent": userAgent, accept: body.accept },
  });
  const contentType = firstHeader(res.headers["content-type"]);
  const isRedirect = REDIRECT_STATUSES.has(res.statusCode) && res.headers.location !== undefined;
  // Redirect bodies are never inspected; only the final response's body is.
  if (isRedirect || body.maxBytes === 0 || !body.wants(res.statusCode, contentType)) {
    // Drain (bounded) so the socket can be released.
    await res.body.dump({ limit: DRAIN_LIMIT });
    const { statusCode, headers } = res;
    return { statusCode, headers, body: undefined, bodyBytes: 0, bodyTruncated: false };
  }
  const { bytes, truncated } = await readBounded(res.body, body.maxBytes);
  const text = decoderFor(parseContentType(contentType).charset).decode(bytes);
  return {
    statusCode: res.statusCode,
    headers: res.headers,
    body: text,
    bodyBytes: bytes.length,
    bodyTruncated: truncated,
  };
}

/** The response a redirect chain ended on. */
interface ChainEnd {
  url: URL;
  response: HopResponse;
  redirects: readonly RedirectHop[];
}

/**
 * Requests `rawUrl` and follows redirects under the SSRF policy, re-validating
 * every hop. Shared by `scanUrl()` and `fetchText()` so both get exactly the
 * same guard, timeouts and redirect limits.
 */
async function followChain(
  rawUrl: string,
  opts: ResolvedOptions,
  bodyPolicy: BodyPolicy,
): Promise<ChainEnd> {
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
        res = await fetchOnce(current, agent, signal, opts.userAgent, bodyPolicy);
      } catch (err) {
        throw toScanError(err, current.href, outcome, deadline, opts.signal);
      }

      const location = firstHeader(res.headers.location);
      const isRedirect = REDIRECT_STATUSES.has(res.statusCode) && location !== undefined;
      if (!isRedirect || !opts.followRedirects) {
        return { url: current, response: res, redirects: Object.freeze(redirects) };
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
  } catch (err) {
    // Attach the chain so callers can see how far the scan got (e.g. it did reach https).
    if (err instanceof ScanError && err.redirects.length === 0 && redirects.length > 0) {
      throw new ScanError(err.code, err.message, {
        url: err.url,
        cause: err.cause,
        redirects,
      });
    }
    throw err;
  } finally {
    await agent.destroy();
  }
}

/**
 * Fetches `rawUrl` and grades the final response's security headers.
 *
 * @throws ScanError with a stable `code` for bad input, blocked targets,
 *   redirect problems, timeouts and network failures.
 */
export async function scanUrl(rawUrl: string, options: ScanOptions = {}): Promise<ScanResult> {
  const opts = resolveOptions(options);
  const { url, response, redirects } = await followChain(rawUrl, opts, {
    accept: "text/html,*/*;q=0.8",
    maxBytes: opts.maxBodyBytes,
    wants: (_status, contentType) => isHtmlResponse(contentType),
  });
  const headers = new HeaderMap(response.headers as HeaderInput);
  const findings = runAll(headers, { isHttps: url.protocol === "https:" });
  const report = buildReport(url.href, response.statusCode, findings);
  const content = buildContentReport({
    pageUrl: url.href,
    headers,
    redirects,
    html: response.body,
    bodyBytes: response.bodyBytes,
    bodyTruncated: response.bodyTruncated,
    ...(options.firstPartyHosts === undefined ? {} : { firstPartyHosts: options.firstPartyHosts }),
  });
  return Object.freeze({ report, redirects, content });
}

/** Default and maximum bytes `fetchText()` reads. Small: it's for policy files, not pages. */
export const DEFAULT_TEXT_BYTES = 64 * 1024;

export interface FetchTextOptions extends Omit<ScanOptions, "maxBodyBytes"> {
  /** Bytes of a 2xx body to read; larger bodies are truncated. Default 64 KiB, max 10 MiB. */
  maxBytes?: number;
  /** Accept header to send. Defaults to preferring text/plain. */
  accept?: string;
}

export interface TextFetchResult {
  /** The URL that produced the final response (after redirects). */
  readonly url: string;
  readonly statusCode: number;
  /** Content-Type header of the final response, if any. */
  readonly contentType: string | undefined;
  /** Decoded body of a 2xx response; undefined for any other status. */
  readonly text: string | undefined;
  readonly bytes: number;
  readonly truncated: boolean;
  readonly redirects: readonly RedirectHop[];
}

/**
 * Fetches a small text resource (robots.txt, security.txt...) under the same
 * SSRF policy, timeouts and redirect rules as `scanUrl()`. Only 2xx bodies are
 * read, and never more than `maxBytes`; non-2xx statuses are returned, not
 * thrown, so callers can tell "missing" from "unreachable".
 *
 * @throws ScanError for bad input, blocked targets, redirect problems,
 *   timeouts and network failures.
 */
export async function fetchText(
  rawUrl: string,
  options: FetchTextOptions = {},
): Promise<TextFetchResult> {
  const { maxBytes = DEFAULT_TEXT_BYTES, accept = "text/plain, */*;q=0.5", ...rest } = options;
  if (accept.length === 0 || accept.length > 256 || /[\r\n\0]/.test(accept)) {
    throw invalidOption("accept must be 1-256 characters without CR, LF or NUL");
  }
  const opts = resolveOptions({ ...rest, maxBodyBytes: maxBytes });
  const { url, response, redirects } = await followChain(rawUrl, opts, {
    accept,
    maxBytes: opts.maxBodyBytes,
    wants: (status) => status >= 200 && status < 300,
  });
  return Object.freeze({
    url: url.href,
    statusCode: response.statusCode,
    contentType: firstHeader(response.headers["content-type"]),
    text: response.body,
    bytes: response.bodyBytes,
    truncated: response.bodyTruncated,
    redirects,
  });
}
