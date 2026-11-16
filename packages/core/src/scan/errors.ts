import type { RedirectHop } from "./scan-url.js";

/** Why a scan could not produce a report. Stable strings: the API stores them. */
export type ScanErrorCode =
  | "INVALID_URL"
  | "INVALID_OPTIONS"
  | "BLOCKED_SCHEME"
  | "BLOCKED_ADDRESS"
  | "DNS_FAILURE"
  | "TOO_MANY_REDIRECTS"
  | "REDIRECT_LOOP"
  | "TIMEOUT"
  | "ABORTED"
  | "TLS_ERROR"
  | "NETWORK";

export class ScanError extends Error {
  override readonly name = "ScanError";
  readonly code: ScanErrorCode;
  /** The URL being fetched when the scan failed (the hop, not always the start URL). */
  readonly url: string | undefined;
  /** Redirects followed before the failure (empty if it failed on the first request). */
  readonly redirects: readonly RedirectHop[];

  constructor(
    code: ScanErrorCode,
    message: string,
    options: { url?: string | undefined; cause?: unknown; redirects?: readonly RedirectHop[] } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.code = code;
    this.url = options.url;
    this.redirects = Object.freeze([...(options.redirects ?? [])]);
  }
}

export function isScanError(value: unknown): value is ScanError {
  return value instanceof ScanError;
}
