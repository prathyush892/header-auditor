/**
 * @header-auditor/core — the TypeScript scan engine.
 *
 * A pure (no network, no I/O) port of the Python checks. Each check takes a
 * HeaderMap and returns a Finding; behaviour is pinned to the Python engine by
 * the shared cases in spec/parity/checks.json.
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
