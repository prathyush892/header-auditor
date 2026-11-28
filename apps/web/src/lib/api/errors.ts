/**
 * Three ways a call can fail, as three classes, so the UI can branch on
 * `instanceof` instead of parsing messages:
 *
 *   ApiError          the API answered with an error status (has a `code`)
 *   ApiNetworkError   no answer: offline, DNS, refused, timed out
 *   ApiResponseError  an answer we don't understand (wrong shape, not JSON)
 */
import type { ErrorDetail } from "./schemas";

export interface ApiErrorInit {
  readonly status: number;
  readonly code: string;
  readonly message: string;
  readonly requestId?: string | null;
  readonly details?: readonly ErrorDetail[];
  readonly retryAfterSeconds?: number | null;
}

/** Code used when the error body isn't ours (e.g. an HTML 502 from a proxy). */
export const UNEXPECTED_RESPONSE = "UNEXPECTED_RESPONSE";

export class ApiError extends Error {
  override readonly name = "ApiError";
  readonly status: number;
  readonly code: string;
  /** Quote this when reporting a problem; the API logs the cause under it. */
  readonly requestId: string | null;
  readonly details: readonly ErrorDetail[];
  /** From `Retry-After` on 429s, in whole seconds. */
  readonly retryAfterSeconds: number | null;

  constructor(init: ApiErrorInit) {
    super(init.message);
    this.status = init.status;
    this.code = init.code;
    this.requestId = init.requestId ?? null;
    this.details = init.details ?? [];
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
  }
}

export class ApiNetworkError extends Error {
  override readonly name = "ApiNetworkError";
  readonly timedOut: boolean;

  constructor(message: string, options: { readonly timedOut?: boolean; readonly cause?: unknown }) {
    super(message, { cause: options.cause });
    this.timedOut = options.timedOut ?? false;
  }
}

export class ApiResponseError extends Error {
  override readonly name = "ApiResponseError";
  readonly status: number;
  readonly path: string;

  constructor(message: string, options: { status: number; path: string; cause?: unknown }) {
    super(message, { cause: options.cause });
    this.status = options.status;
    this.path = options.path;
  }
}

/**
 * Groups `details` by field (`{ password: ["must be at least 15 characters"] }`)
 * so a form can show each message next to its input. `<root>` goes to `_form`.
 */
export function fieldErrors(error: ApiError): Readonly<Record<string, readonly string[]>> {
  const grouped = new Map<string, string[]>();
  for (const { path, message } of error.details) {
    const key = path === "<root>" || path === "" ? "_form" : path;
    const list = grouped.get(key);
    if (list === undefined) grouped.set(key, [message]);
    else list.push(message);
  }
  return Object.fromEntries(grouped);
}

/** Parses `Retry-After` (seconds or an HTTP date). Null when absent or invalid. */
export function parseRetryAfter(value: string | null, now: number = Date.now()): number | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (/^\d{1,9}$/.test(trimmed)) return Number(trimmed);
  // HTTP dates always end in GMT (RFC 9110). Without this check Date.parse
  // happily reads "-5" as the year -5.
  if (!/^[A-Za-z]{3},? .* GMT$/.test(trimmed)) return null;
  const at = Date.parse(trimmed);
  if (Number.isNaN(at)) return null;
  return Math.max(0, Math.ceil((at - now) / 1_000));
}

/** One human sentence for any error the client can throw. */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 429) {
      return error.retryAfterSeconds === null
        ? "Too many attempts. Try again later."
        : `Too many attempts. Try again in ${formatWait(error.retryAfterSeconds)}.`;
    }
    if (error.status >= 500 || error.code === UNEXPECTED_RESPONSE) {
      const ref = error.requestId === null ? "" : ` (reference ${error.requestId})`;
      return `Something went wrong on our side${ref}. Please try again.`;
    }
    return error.message;
  }
  if (error instanceof ApiNetworkError) {
    return error.timedOut
      ? "The server took too long to answer. Please try again."
      : "Can't reach the server. Check your connection and try again.";
  }
  return "Something went wrong. Please try again.";
}

function formatWait(seconds: number): string {
  if (seconds < 60) return `${String(Math.max(1, seconds))} seconds`;
  const minutes = Math.ceil(seconds / 60);
  return minutes === 1 ? "1 minute" : `${String(minutes)} minutes`;
}
