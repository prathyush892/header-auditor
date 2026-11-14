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
  | "NETWORK";

export class ScanError extends Error {
  override readonly name = "ScanError";
  readonly code: ScanErrorCode;
  /** The URL being fetched when the scan failed (the hop, not always the start URL). */
  readonly url: string | undefined;

  constructor(
    code: ScanErrorCode,
    message: string,
    options: { url?: string; cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.code = code;
    this.url = options.url;
  }
}

export function isScanError(value: unknown): value is ScanError {
  return value instanceof ScanError;
}
