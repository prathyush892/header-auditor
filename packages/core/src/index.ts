/**
 * @header-auditor/core — the TypeScript scan engine.
 *
 * The checks are a pure (no network, no I/O) port of the Python engine: each
 * takes a HeaderMap and returns a Finding, pinned to Python by the shared cases
 * in spec/parity/checks.json. The only network code lives in `scan/`, where
 * `scanUrl()` fetches a URL under an SSRF policy and feeds the checks, and in
 * `tls/`, where `probeTls()` handshakes under the same policy. `content/` holds
 * the redirect-chain and mixed-content checks plus `probeHttpsRedirect()`.
 * `dns/` runs CAA, SPF and DMARC checks through an injectable `DnsResolver`.
 */

/** Semantic version of the scan engine, reported alongside every scan result. */
export const ENGINE_VERSION = "0.0.0";

/** Identifies which engine produced a result (the Python CLI or this package). */
export type EngineName = "header-auditor-core" | "header-auditor-python";

export const ENGINE_NAME: EngineName = "header-auditor-core";

export { makeFinding, Status, type Finding, type FindingInit } from "./finding.js";
export { HeaderMap, type HeaderEntry, type HeaderInput } from "./headers.js";
export {
  effectiveScriptSources,
  findAnyOriginSource,
  hasSource,
  hasSourcePrefix,
  neutralizesUnsafeInline,
  parseCsp,
  type CspPolicy,
} from "./csp.js";
export * from "./checks/index.js";
export {
  buildReport,
  GRADE_CUTOFFS,
  gradeFor,
  reportToJson,
  roundHalfEven,
  runAll,
  scoreFindings,
  type Grade,
  type Report,
  type ReportJson,
  type RunOptions,
  type Score,
} from "./report.js";
export * from "./scan/index.js";
export * from "./tls/index.js";
export * from "./content/index.js";
export * from "./dns/index.js";
