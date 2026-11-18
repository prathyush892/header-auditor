/**
 * Fetches a site's well-known files (security.txt, robots.txt) and grades
 * them as their own report section, like the TLS, content and DNS reports.
 *
 * Every request goes through `fetchText()`, so it gets the same scheme
 * allow-list, SSRF guard, timeouts and redirect limits as a normal scan. Only
 * these fixed paths on the target's own origin are requested; paths listed
 * inside robots.txt are never fetched.
 */
import type { Finding } from "../finding.js";
import { scoreFindings, type Score } from "../report.js";
import { parseAllowList } from "../scan/address.js";
import { ScanError, type ScanErrorCode } from "../scan/errors.js";
import {
  fetchText,
  isHtmlResponse,
  parseContentType,
  validateTarget,
  type ScanOptions,
} from "../scan/scan-url.js";
import type { WellKnownObservation } from "./observation.js";
import {
  checkRobotsTxt,
  findSensitivePaths,
  parseRobotsTxt,
  ROBOTS_TXT_MAX_BYTES,
  ROBOTS_TXT_PATH,
  type SensitivePath,
} from "./robots-txt.js";
import {
  checkSecurityTxt,
  parseSecurityTxt,
  SECURITY_TXT_LEGACY_PATH,
  SECURITY_TXT_MAX_BYTES,
  SECURITY_TXT_PATH,
  type ParsedSecurityTxt,
} from "./security-txt.js";

export interface WellKnownOptions extends Omit<ScanOptions, "followRedirects" | "maxBodyBytes"> {
  /** Clock for security.txt's Expires; injectable for tests. */
  now?: Date;
}

export interface WellKnownReport extends Score {
  /** Origin the files were requested from. */
  readonly origin: string;
  readonly findings: readonly Finding[];
  readonly securityTxt: {
    readonly observation: WellKnownObservation;
    /** Parsed fields, when a file was found. */
    readonly parsed: ParsedSecurityTxt | undefined;
  };
  readonly robotsTxt: {
    readonly observation: WellKnownObservation;
    readonly sensitivePaths: readonly SensitivePath[];
  };
}

/** Errors that mean the caller can't scan this target at all; they're re-thrown. */
const ALWAYS_RETHROW: ReadonlySet<ScanErrorCode> = new Set(["INVALID_OPTIONS", "ABORTED"]);

/**
 * Requests `path` on `origin` and classifies the outcome. A 2xx text response
 * is "found"; non-2xx, HTML (an SPA or CMS catch-all page) and empty bodies
 * are "missing"; network-level failures are "error".
 */
export async function fetchWellKnown(
  origin: string,
  path: string,
  maxBytes: number,
  options: Omit<WellKnownOptions, "now"> = {},
): Promise<WellKnownObservation> {
  const url = new URL(path, origin).href;
  try {
    const res = await fetchText(url, { ...options, maxBytes, followRedirects: true });
    if (res.text === undefined) {
      return {
        kind: "missing",
        url,
        path,
        statusCode: res.statusCode,
        reason: `HTTP ${String(res.statusCode)}`,
      };
    }
    const mediaType = parseContentType(res.contentType).mediaType;
    if (res.contentType !== undefined && isHtmlResponse(res.contentType)) {
      return {
        kind: "missing",
        url,
        path,
        statusCode: res.statusCode,
        reason: "served as HTML, likely a catch-all page",
      };
    }
    if (res.text.trim() === "") {
      return { kind: "missing", url, path, statusCode: res.statusCode, reason: "empty file" };
    }
    return {
      kind: "found",
      url,
      path,
      finalUrl: res.url,
      statusCode: res.statusCode,
      mediaType,
      text: res.text,
      truncated: res.truncated,
      redirects: res.redirects,
    };
  } catch (err) {
    if (!(err instanceof ScanError) || ALWAYS_RETHROW.has(err.code)) throw err;
    // The target host itself is blocked by the SSRF policy: that's the caller's problem.
    if (err.code === "BLOCKED_ADDRESS" && err.redirects.length === 0 && err.url === url) throw err;
    return { kind: "error", url, path, code: err.code };
  }
}

/** Tries `/.well-known/security.txt`, then the legacy top-level path if that's missing. */
async function fetchSecurityTxt(
  origin: string,
  options: Omit<WellKnownOptions, "now">,
): Promise<WellKnownObservation> {
  const primary = await fetchWellKnown(origin, SECURITY_TXT_PATH, SECURITY_TXT_MAX_BYTES, options);
  if (primary.kind !== "missing") return primary;
  const legacy = await fetchWellKnown(
    origin,
    SECURITY_TXT_LEGACY_PATH,
    SECURITY_TXT_MAX_BYTES,
    options,
  );
  return legacy.kind === "found" ? legacy : primary;
}

/**
 * Fetches and grades security.txt and robots.txt for `target`'s origin
 * (scheme, host and port; the path is ignored).
 *
 * @throws ScanError for invalid input or options, a blocked target, or cancellation.
 */
export async function analyzeWellKnown(
  target: string,
  options: WellKnownOptions = {},
): Promise<WellKnownReport> {
  const { now = new Date(), ...fetchOptions } = options;
  if (Number.isNaN(now.getTime())) {
    throw new ScanError("INVALID_OPTIONS", "now must be a valid Date");
  }
  let allowList;
  try {
    allowList = parseAllowList(fetchOptions.allowAddresses ?? []);
  } catch (err) {
    throw new ScanError("INVALID_OPTIONS", err instanceof Error ? err.message : String(err));
  }
  // Vet the target before any request: scheme, credentials, IP-literal policy.
  const url = validateTarget(target, {
    allowPrivate: fetchOptions.allowPrivate ?? false,
    allowList,
  });
  const origin = url.origin;

  const [security, robots] = await Promise.all([
    fetchSecurityTxt(origin, fetchOptions),
    fetchWellKnown(origin, ROBOTS_TXT_PATH, ROBOTS_TXT_MAX_BYTES, fetchOptions),
  ]);
  const findings = Object.freeze([checkSecurityTxt(security, now), checkRobotsTxt(robots)]);
  return Object.freeze({
    origin,
    findings,
    securityTxt: Object.freeze({
      observation: security,
      parsed: security.kind === "found" ? parseSecurityTxt(security.text) : undefined,
    }),
    robotsTxt: Object.freeze({
      observation: robots,
      sensitivePaths: Object.freeze(
        robots.kind === "found" ? findSensitivePaths(parseRobotsTxt(robots.text).rules) : [],
      ),
    }),
    ...scoreFindings(findings),
  });
}
