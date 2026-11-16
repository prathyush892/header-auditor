/**
 * The "content" section of a scan: checks that need more than the final
 * response's headers (the redirect chain and the HTML body). Scored on its
 * own, like the TLS report, so the header score stays at parity with the
 * Python CLI.
 */
import type { Finding } from "../finding.js";
import type { HeaderMap } from "../headers.js";
import { scoreFindings, type Score } from "../report.js";
import type { RedirectHop } from "../scan/scan-url.js";
import { checkMixedContent, type MixedContentRef } from "./mixed-content.js";
import { checkRedirectChain } from "./redirects.js";

export interface ContentReport extends Score {
  readonly findings: readonly Finding[];
  /** Every insecure reference found in the page (also summarised in the findings). */
  readonly mixedContent: readonly MixedContentRef[];
  /** Whether a CSP `upgrade-insecure-requests` (header or meta) was in effect. */
  readonly upgradeInsecureRequests: boolean;
  /** Bytes of HTML inspected, 0 when the body wasn't read. */
  readonly bodyBytes: number;
  /** True when the body was larger than the read limit. */
  readonly bodyTruncated: boolean;
}

export interface ContentInput {
  readonly pageUrl: string;
  readonly headers: HeaderMap;
  readonly redirects: readonly RedirectHop[];
  readonly html: string | undefined;
  readonly bodyBytes: number;
  readonly bodyTruncated: boolean;
}

export function buildContentReport(input: ContentInput): ContentReport {
  const mixed = checkMixedContent({
    pageUrl: input.pageUrl,
    html: input.html,
    headers: input.headers,
    truncated: input.bodyTruncated,
  });
  const findings = Object.freeze([checkRedirectChain(input.redirects), mixed.finding]);
  return Object.freeze({
    findings,
    mixedContent: mixed.references,
    upgradeInsecureRequests: mixed.upgradeInsecureRequests,
    bodyBytes: input.bodyBytes,
    bodyTruncated: input.bodyTruncated,
    ...scoreFindings(findings),
  });
}
