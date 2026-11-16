/**
 * `probeHttpsRedirect()`: requests the plain-http address of a site and
 * reports whether it upgrades visitors to HTTPS.
 *
 * It reuses `scanUrl()` for the request, so every hop goes through the same
 * scheme allow-list, SSRF guard, timeouts and redirect limits as a normal scan.
 */
import type { Finding } from "../finding.js";
import { parseAllowList } from "../scan/address.js";
import { ScanError, type ScanErrorCode } from "../scan/errors.js";
import { scanUrl, validateTarget, type RedirectHop, type ScanOptions } from "../scan/scan-url.js";
import { analyzeHttpsRedirect, type HttpObservation } from "./redirects.js";

export interface HttpsRedirectOptions extends Omit<
  ScanOptions,
  "followRedirects" | "maxBodyBytes"
> {
  /**
   * Port to try plain HTTP on. Defaults to the URL's own port for an http://
   * URL, otherwise 80. (An https://host:8443 URL says nothing about which port
   * serves HTTP, so the standard port is assumed unless told otherwise.)
   */
  httpPort?: number;
}

export interface HttpsRedirectResult {
  /** The http:// URL that was requested. */
  readonly httpUrl: string;
  readonly finding: Finding;
  readonly redirects: readonly RedirectHop[];
  /** Where the chain ended, when it ended in a response. */
  readonly finalUrl: string | undefined;
  /** Why the chain stopped, when it ended in an error. */
  readonly errorCode: ScanErrorCode | undefined;
}

/**
 * Errors that describe the *target*, not the site's behaviour: bad input or a
 * blocked address. These are re-thrown instead of being graded.
 */
const CALLER_ERRORS: ReadonlySet<ScanErrorCode> = new Set([
  "INVALID_URL",
  "INVALID_OPTIONS",
  "BLOCKED_SCHEME",
  "BLOCKED_ADDRESS",
  "ABORTED",
]);

/** Builds the http:// URL to probe for `target` (same host and path, query dropped). */
export function httpVariant(target: string, httpPort?: number): URL {
  if (
    httpPort !== undefined &&
    (!Number.isInteger(httpPort) || httpPort < 1 || httpPort > 65_535)
  ) {
    throw new ScanError("INVALID_OPTIONS", "httpPort must be an integer between 1 and 65535");
  }
  // Scheme, credentials and length are vetted here; the address policy is applied by scanUrl.
  const source = validateTarget(target, { allowPrivate: true, allowList: parseAllowList([]) });
  const url = new URL(source.href);
  const port = httpPort ?? (source.protocol === "http:" ? source.port : "");
  url.protocol = "http:";
  url.port = port === "" ? "" : String(port);
  url.search = "";
  return url;
}

/**
 * Requests `http://<host>/<path>` for `target`, follows redirects and grades
 * the result with `analyzeHttpsRedirect`.
 *
 * @throws ScanError for invalid input, blocked addresses or cancellation.
 */
export async function probeHttpsRedirect(
  target: string,
  options: HttpsRedirectOptions = {},
): Promise<HttpsRedirectResult> {
  const { httpPort, ...scanOptions } = options;
  const httpUrl = httpVariant(target, httpPort);

  let observation: HttpObservation;
  try {
    // Only the chain matters here, so skip reading any HTML.
    const result = await scanUrl(httpUrl.href, {
      ...scanOptions,
      followRedirects: true,
      maxBodyBytes: 0,
    });
    observation = {
      kind: "response",
      redirects: result.redirects,
      finalUrl: result.report.url,
      statusCode: result.report.statusCode,
    };
  } catch (err) {
    if (!(err instanceof ScanError) || CALLER_ERRORS.has(err.code)) throw err;
    observation = {
      kind: "error",
      redirects: err.redirects,
      code: err.code,
      failedUrl: err.url ?? httpUrl.href,
    };
  }

  return Object.freeze({
    httpUrl: httpUrl.href,
    finding: analyzeHttpsRedirect(httpUrl, observation),
    redirects: observation.redirects,
    finalUrl: observation.kind === "response" ? observation.finalUrl : undefined,
    errorCode: observation.kind === "error" ? observation.code : undefined,
  });
}
