/**
 * One full scan of a site with @header-auditor/core.
 *
 * Phase 1 fetches the page (headers, redirects, mixed content, SRI). It is
 * required: if the site can't be fetched there is nothing to grade, and the
 * scan fails with a user-safe reason.
 *
 * Phase 2 runs the TLS, DNS and well-known checks in parallel. Each is
 * optional: one failing (a DNS timeout, say) is recorded in the report and
 * the rest of the scan still succeeds.
 *
 * Every network call goes through core's SSRF guard (`allowPrivate` false by
 * default), which checks the address each hostname resolves to at connect
 * time. The API refused IP literals and localhost when the site was added,
 * but that check can't see DNS answers, so this one is the real control.
 */
import { isIP } from "node:net";

import {
  analyzeDns,
  analyzeWellKnown,
  type ContentReport,
  type DnsReport,
  type DnsResolver,
  ENGINE_NAME,
  ENGINE_VERSION,
  type Finding,
  isScanError,
  probeTls,
  type RedirectHop,
  type Report,
  type Resolver,
  scanUrl,
  type ScanErrorCode,
  type TlsReport,
  type WellKnownReport,
} from "@header-auditor/core";
import {
  type EngineFinding,
  type FindingCategory,
  findingRows,
  type FindingRow,
  stripNul,
} from "@header-auditor/db";

export interface EngineOptions {
  /** Budget for each phase (core caps a single call at 120 s). */
  readonly timeoutMs: number;
  readonly allowPrivate: boolean;
  readonly firstPartyHosts: readonly string[];
  /** Hostname -> addresses for HTTP and TLS connections. Tests inject fixtures. */
  readonly resolver?: Resolver;
  /** CAA/TXT lookups for the DNS checks. Tests inject fixtures. */
  readonly dnsResolver?: DnsResolver;
  /** PEM CA(s) to trust instead of the system roots (tests with a local TLS server). */
  readonly ca?: string | readonly string[];
  readonly now?: () => Date;
  readonly signal?: AbortSignal;
}

export type Section<T> =
  | { readonly status: "ok"; readonly report: T }
  | { readonly status: "skipped"; readonly reason: string }
  | { readonly status: "error"; readonly code: string; readonly message: string };

export interface EngineResult {
  readonly engine: { readonly name: string; readonly version: string };
  readonly requestedUrl: string;
  readonly finalUrl: string;
  readonly httpStatus: number;
  /** The headline grade: the header report, at parity with the Python CLI. */
  readonly score: number;
  readonly grade: Report["grade"];
  readonly redirects: readonly RedirectHop[];
  readonly headers: Report;
  readonly content: ContentReport;
  readonly tls: Section<TlsReport>;
  readonly dns: Section<DnsReport>;
  readonly wellKnown: Section<WellKnownReport>;
}

/**
 * Raised when phase 1 fails because of the *target* (refused, timed out,
 * blocked by the SSRF policy). The scan is a FAILED result, not a retry.
 */
export class TargetError extends Error {
  override readonly name = "TargetError";

  constructor(
    readonly code: ScanErrorCode,
    /** Fixed, user-safe text (stored on the scan, shown in the dashboard). */
    readonly userMessage: string,
    options: { cause?: unknown } = {},
  ) {
    super(userMessage, options);
  }
}

/**
 * Stored reasons per core error code. Fixed strings, never `err.message`:
 * that can include resolver output or addresses we'd rather not show, and
 * stays stable for the UI.
 */
export const FAILURE_MESSAGES: Readonly<Record<ScanErrorCode, string>> = {
  INVALID_URL: "The site URL is not valid.",
  INVALID_OPTIONS: "The scan was misconfigured.",
  BLOCKED_SCHEME: "The site redirected to a URL scheme that is not scanned.",
  BLOCKED_ADDRESS:
    "The site resolves to a private or reserved network address, which is not scanned.",
  DNS_FAILURE: "The site's hostname could not be resolved.",
  TOO_MANY_REDIRECTS: "The site redirected too many times.",
  REDIRECT_LOOP: "The site redirects in a loop.",
  TIMEOUT: "The site did not respond in time.",
  ABORTED: "The scan was cancelled.",
  TLS_ERROR: "A TLS connection to the site could not be established.",
  NETWORK: "The site could not be reached.",
};

function hostnameOf(url: string): string {
  return new URL(url).hostname.replace(/^\[(.*)\]$/, "$1");
}

function sectionError(error: unknown): Section<never> {
  if (isScanError(error)) {
    return { status: "error", code: error.code, message: FAILURE_MESSAGES[error.code] };
  }
  return { status: "error", code: "INTERNAL", message: "This check failed unexpectedly." };
}

async function optional<T>(run: () => Promise<T>): Promise<Section<T>> {
  try {
    return { status: "ok", report: await run() };
  } catch (error) {
    return sectionError(error);
  }
}

function networkOptions(options: EngineOptions) {
  return {
    timeoutMs: options.timeoutMs,
    allowPrivate: options.allowPrivate,
    ...(options.resolver === undefined ? {} : { resolver: options.resolver }),
    ...(options.ca === undefined ? {} : { ca: options.ca }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  };
}

export async function runEngine(target: string, options: EngineOptions): Promise<EngineResult> {
  const net = networkOptions(options);
  let page;
  try {
    page = await scanUrl(target, { ...net, firstPartyHosts: options.firstPartyHosts });
  } catch (error) {
    if (isScanError(error)) {
      throw new TargetError(error.code, FAILURE_MESSAGES[error.code], { cause: error });
    }
    throw error;
  }

  const finalUrl = page.report.url;
  const domain = hostnameOf(target);
  const now = options.now ?? (() => new Date());

  const [tls, dns, wellKnown] = await Promise.all([
    new URL(finalUrl).protocol === "https:"
      ? optional(() => probeTls(finalUrl, net))
      : Promise.resolve<Section<TlsReport>>({
          status: "skipped",
          reason: "The site was not served over HTTPS.",
        }),
    isIP(domain) === 0
      ? optional(() =>
          analyzeDns(
            domain,
            options.dnsResolver === undefined ? {} : { resolver: options.dnsResolver },
          ),
        )
      : Promise.resolve<Section<DnsReport>>({
          status: "skipped",
          reason: "DNS checks need a hostname, not an IP address.",
        }),
    optional(() => analyzeWellKnown(finalUrl, { ...net, now: now() })),
  ]);

  return {
    engine: { name: ENGINE_NAME, version: ENGINE_VERSION },
    requestedUrl: target,
    finalUrl,
    httpStatus: page.report.statusCode,
    score: page.report.score,
    grade: page.report.grade,
    redirects: page.redirects,
    headers: page.report,
    content: page.content,
    tls,
    dns,
    wellKnown,
  };
}

function findingsOf<T extends { readonly findings: readonly Finding[] }>(
  section: Section<T>,
): readonly EngineFinding[] {
  return section.status === "ok" ? section.report.findings : [];
}

/** Every finding, numbered across sections in report order. */
export function engineFindingRows(result: EngineResult): FindingRow[] {
  const sections: (readonly [FindingCategory, readonly EngineFinding[]])[] = [
    ["HEADERS", result.headers.findings],
    ["CONTENT", result.content.findings],
    ["TLS", findingsOf(result.tls)],
    ["DNS", findingsOf(result.dns)],
    ["WELL_KNOWN", findingsOf(result.wellKnown)],
  ];
  return findingRows(sections);
}

/**
 * The report as stored in `scans.report` (jsonb). Strings are stripped of NUL
 * characters, which Postgres rejects in jsonb and a hostile page could put in
 * a header to make its own scan unsavable. Dates become ISO strings.
 */
export function storedReport(result: EngineResult): unknown {
  const json = JSON.stringify(result, (_key, value: unknown) =>
    typeof value === "string" ? stripNul(value) : value,
  );
  return JSON.parse(json) as unknown;
}
