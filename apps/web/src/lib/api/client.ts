/**
 * Typed client for the header-auditor API.
 *
 * - Every response is validated against a zod schema before it is returned.
 * - The CSRF token is kept in memory (never localStorage) and sent as
 *   `x-csrf-token` on unsafe methods. It comes from login/register/session.
 * - The session itself is an httpOnly cookie that JavaScript can't read; the
 *   browser attaches it because the dashboard reaches the API on its own
 *   origin (`/api/*` is proxied by Next.js, see next.config.ts).
 * - Requests time out, and failures surface as ApiError / ApiNetworkError /
 *   ApiResponseError (see errors.ts).
 */
import type { z } from "zod";

import {
  ApiError,
  ApiNetworkError,
  ApiResponseError,
  parseRetryAfter,
  UNEXPECTED_RESPONSE,
} from "./errors";
import {
  type Credentials,
  type CurrentSession,
  currentSessionSchema,
  errorBodySchema,
  type Health,
  healthSchema,
  type SessionResponse,
  sessionResponseSchema,
} from "./schemas";

/** Browser-facing prefix that next.config.ts proxies to the API. */
export const API_PROXY_PREFIX = "/api";
export const CSRF_HEADER = "x-csrf-token";
export const REQUEST_ID_HEADER = "x-request-id";
export const DEFAULT_TIMEOUT_MS = 15_000;

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
const UNSAFE_METHODS: ReadonlySet<HttpMethod> = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Paths are fixed strings built by this module, never URLs from user input. */
const PATH_PART = /^\/(?!\/)[A-Za-z0-9\-._~/%]*$/;
const QUERY_PART = /^[A-Za-z0-9\-._~%=&]*$/;

/** `/sites/abc?cursor=x` is fine; `//host`, `/a b`, `/x#y` and `?a?b` are not. */
export function isValidApiPath(path: string): boolean {
  const [pathname = "", query, ...rest] = path.split("?");
  if (rest.length > 0) return false;
  return PATH_PART.test(pathname) && (query === undefined || QUERY_PART.test(query));
}

/** `application/json`, `application/problem+json`, with or without parameters. */
export function isJsonContentType(value: string | null): boolean {
  const essence = (value ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
  return (
    essence === "application/json" ||
    (essence.startsWith("application/") && essence.endsWith("+json"))
  );
}

export interface ApiClientOptions {
  /** `/api` in the browser (same origin), or an absolute `http(s)://` URL. */
  readonly baseUrl: string;
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
  /** Called when the API says the session is gone (401 AUTH_REQUIRED). */
  readonly onUnauthorized?: () => void;
}

export interface CallOptions {
  readonly signal?: AbortSignal;
}

export interface ApiClient {
  /** Current CSRF token, or null when signed out. */
  readonly csrfToken: string | null;
  health(options?: CallOptions): Promise<Health>;
  register(credentials: Credentials, options?: CallOptions): Promise<SessionResponse>;
  login(credentials: Credentials, options?: CallOptions): Promise<SessionResponse>;
  /** The signed-in session, or null when there is none (a 401 is not an error here). */
  session(options?: CallOptions): Promise<CurrentSession | null>;
  logout(options?: CallOptions): Promise<void>;
  logoutAll(options?: CallOptions): Promise<void>;
}

interface RequestSpec<T> {
  readonly method: HttpMethod;
  readonly path: string;
  readonly body?: unknown;
  /** Omit for endpoints that answer 204 No Content. */
  readonly schema?: z.ZodType<T>;
  readonly signal?: AbortSignal | undefined;
}

/** `/api/` → `/api`; rejects anything that isn't a path or an http(s) URL. */
export function normalizeBaseUrl(baseUrl: string): string {
  const trimmed = baseUrl.trim().replace(/\/+$/, "");
  if (trimmed === "" || trimmed.startsWith("/")) {
    if (trimmed.startsWith("//")) throw new TypeError("baseUrl must not be protocol-relative");
    return trimmed;
  }
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new TypeError(
      `baseUrl must be a path or an absolute URL, got ${JSON.stringify(baseUrl)}`,
    );
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new TypeError(`baseUrl must use http or https, got ${url.protocol}`);
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    throw new TypeError("baseUrl must not contain credentials, a query or a fragment");
  }
  return trimmed;
}

function isAbortError(error: unknown, name: "AbortError" | "TimeoutError"): boolean {
  return error instanceof Error && error.name === name;
}

export function createApiClient(options: ApiClientOptions): ApiClient {
  const baseUrl = normalizeBaseUrl(options.baseUrl);
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError("timeoutMs must be a positive integer");
  }
  let csrfToken: string | null = null;

  async function send(spec: RequestSpec<unknown>): Promise<Response> {
    if (!isValidApiPath(spec.path)) throw new TypeError(`Invalid API path: ${spec.path}`);
    const headers = new Headers({ accept: "application/json" });
    if (spec.body !== undefined) headers.set("content-type", "application/json");
    if (UNSAFE_METHODS.has(spec.method) && csrfToken !== null) {
      headers.set(CSRF_HEADER, csrfToken);
    }
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = spec.signal === undefined ? timeout : AbortSignal.any([spec.signal, timeout]);
    try {
      return await fetchImpl(`${baseUrl}${spec.path}`, {
        method: spec.method,
        headers,
        ...(spec.body === undefined ? {} : { body: JSON.stringify(spec.body) }),
        // Same-origin only: the session cookie must never ride along to another site.
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        signal,
      });
    } catch (error) {
      // The caller cancelled (navigated away): not a failure, let it propagate as-is.
      if (spec.signal?.aborted === true && !timeout.aborted) throw error;
      const timedOut = timeout.aborted || isAbortError(error, "TimeoutError");
      throw new ApiNetworkError(timedOut ? "Request timed out" : "Network request failed", {
        timedOut,
        cause: error,
      });
    }
  }

  async function readJson(response: Response, path: string): Promise<unknown> {
    const type = response.headers.get("content-type") ?? "";
    if (!isJsonContentType(type)) {
      throw new ApiResponseError(`Expected JSON from ${path}, got ${type || "no content type"}`, {
        status: response.status,
        path,
      });
    }
    try {
      return await response.json();
    } catch (error) {
      throw new ApiResponseError(`Invalid JSON from ${path}`, {
        status: response.status,
        path,
        cause: error,
      });
    }
  }

  async function toApiError(response: Response): Promise<ApiError> {
    const headerRequestId = response.headers.get(REQUEST_ID_HEADER);
    const retryAfterSeconds = parseRetryAfter(response.headers.get("retry-after"));
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      // Not JSON (a proxy's HTML error page, an empty body): handled below.
    }
    const parsed = errorBodySchema.safeParse(body);
    if (!parsed.success) {
      return new ApiError({
        status: response.status,
        code: UNEXPECTED_RESPONSE,
        message: `Unexpected ${String(response.status)} response`,
        requestId: headerRequestId,
        retryAfterSeconds,
      });
    }
    const { code, message, requestId, details } = parsed.data.error;
    return new ApiError({
      status: response.status,
      code,
      message,
      requestId: requestId === "" ? headerRequestId : requestId,
      ...(details === undefined ? {} : { details }),
      retryAfterSeconds,
    });
  }

  async function request<T>(spec: RequestSpec<T>, retried = false): Promise<T> {
    const response = await send(spec);
    if (!response.ok) {
      const error = await toApiError(response);
      if (error.status === 401 && error.code === "AUTH_REQUIRED") {
        // Only "unexpected" when we believed we were signed in; probing
        // /auth/session while signed out is the normal way to find out.
        const wasSignedIn = csrfToken !== null;
        csrfToken = null;
        if (wasSignedIn) options.onUnauthorized?.();
      }
      // The CSRF check runs before the route handler, so nothing happened on
      // the server and one retry with a fresh token is safe. A stale token
      // means the session changed (e.g. signed in again in another tab).
      if (error.code === "CSRF_TOKEN_INVALID" && !retried) {
        const current = await fetchSession(spec.signal);
        if (current !== null) return request(spec, true);
      }
      throw error;
    }
    if (spec.schema === undefined) {
      // Drain the body so the connection can be reused.
      await response.arrayBuffer().catch(() => undefined);
      return undefined as T;
    }
    const json = await readJson(response, spec.path);
    const parsed = spec.schema.safeParse(json);
    if (!parsed.success) {
      throw new ApiResponseError(`Unexpected response shape from ${spec.path}`, {
        status: response.status,
        path: spec.path,
        cause: parsed.error,
      });
    }
    return parsed.data;
  }

  async function fetchSession(signal: AbortSignal | undefined): Promise<CurrentSession | null> {
    try {
      const current = await request(
        { method: "GET", path: "/auth/session", schema: currentSessionSchema, signal },
        true,
      );
      csrfToken = current.csrfToken;
      return current;
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        csrfToken = null;
        return null;
      }
      throw error;
    }
  }

  async function startSession(
    path: "/auth/register" | "/auth/login",
    credentials: Credentials,
    signal: AbortSignal | undefined,
  ): Promise<SessionResponse> {
    const result = await request({
      method: "POST",
      path,
      body: { email: credentials.email, password: credentials.password },
      schema: sessionResponseSchema,
      signal,
    });
    csrfToken = result.csrfToken;
    return result;
  }

  async function endSession(path: "/auth/logout" | "/auth/logout-all", signal?: AbortSignal) {
    try {
      await request({ method: "POST", path, signal });
    } finally {
      // Signed out locally even if the request failed; the cookie is the source of truth.
      csrfToken = null;
    }
  }

  return {
    get csrfToken() {
      return csrfToken;
    },
    health: (call = {}) =>
      request({ method: "GET", path: "/health", schema: healthSchema, signal: call.signal }),
    register: (credentials, call = {}) => startSession("/auth/register", credentials, call.signal),
    login: (credentials, call = {}) => startSession("/auth/login", credentials, call.signal),
    session: (call = {}) => fetchSession(call.signal),
    logout: (call = {}) => endSession("/auth/logout", call.signal),
    logoutAll: (call = {}) => endSession("/auth/logout-all", call.signal),
  };
}
