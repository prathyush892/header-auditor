import { describe, expect, it, vi } from "vitest";

import {
  ApiError,
  ApiNetworkError,
  ApiResponseError,
  createApiClient,
  CSRF_HEADER,
  isJsonContentType,
  isValidApiPath,
  normalizeBaseUrl,
  UNEXPECTED_RESPONSE,
} from "@/lib/api";

const USER = { id: "u1", email: "ada@example.com", createdAt: "2026-11-27T10:00:00.000Z" };
const SESSION = { user: USER, csrfToken: "csrf-1", expiresAt: "2026-12-04T10:00:00.000Z" };
const CURRENT = { ...SESSION, idleExpiresAt: "2026-11-27T22:00:00.000Z" };
const CREDS = { email: "ada@example.com", password: "correct horse battery staple" };

interface Call {
  readonly url: string;
  readonly init: RequestInit;
  readonly headers: Headers;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });
}

function errorJson(status: number, code: string, extra: Record<string, unknown> = {}) {
  return json(status, {
    error: { code, message: `${code} message`, requestId: "req-9", ...extra },
  });
}

/** A fetch that answers from a queue and records every call. */
function fakeFetch(...responses: (Response | Error)[]) {
  const calls: Call[] = [];
  const fn = vi.fn((input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    calls.push({ url, init, headers: new Headers(init.headers) });
    const next = responses.shift();
    if (next === undefined) return Promise.reject(new Error("unexpected fetch"));
    return next instanceof Error ? Promise.reject(next) : Promise.resolve(next);
  });
  return { fetch: fn as unknown as typeof fetch, calls };
}

describe("normalizeBaseUrl", () => {
  it.each([
    ["/api/", "/api"],
    ["/api", "/api"],
    ["", ""],
    ["http://127.0.0.1:3001/", "http://127.0.0.1:3001"],
  ])("normalizes %s", (input, expected) => {
    expect(normalizeBaseUrl(input)).toBe(expected);
  });

  it.each(["//evil.example", "ftp://x", "not a url", "http://u:p@host", "http://h/?q=1"])(
    "rejects %s",
    (input) => {
      expect(() => normalizeBaseUrl(input)).toThrow(TypeError);
    },
  );
});

describe("createApiClient", () => {
  it("rejects a non-positive timeout", () => {
    expect(() => createApiClient({ baseUrl: "/api", timeoutMs: 0 })).toThrow(RangeError);
  });

  it("logs in, keeps the CSRF token and sends it on unsafe requests only", async () => {
    const { fetch, calls } = fakeFetch(
      json(200, SESSION),
      json(200, { status: "ok", uptimeSeconds: 3 }),
      new Response(null, { status: 204 }),
    );
    const api = createApiClient({ baseUrl: "/api", fetch });
    expect(api.csrfToken).toBeNull();

    const result = await api.login(CREDS);
    expect(result.user).toEqual(USER);
    expect(api.csrfToken).toBe("csrf-1");
    expect(calls[0]?.url).toBe("/api/auth/login");
    expect(calls[0]?.init.method).toBe("POST");
    expect(calls[0]?.init.credentials).toBe("same-origin");
    expect(calls[0]?.init.redirect).toBe("error");
    expect(calls[0]?.headers.get("content-type")).toBe("application/json");
    expect(calls[0]?.headers.has(CSRF_HEADER)).toBe(false);
    expect(JSON.parse(calls[0]?.init.body as string)).toEqual(CREDS);

    await api.health();
    expect(calls[1]?.headers.has(CSRF_HEADER)).toBe(false);

    await api.logout();
    expect(calls[2]?.headers.get(CSRF_HEADER)).toBe("csrf-1");
    expect(calls[2]?.init.body).toBeUndefined();
    expect(api.csrfToken).toBeNull();
  });

  it("only sends the credentials it was given (no extra fields)", async () => {
    const { fetch, calls } = fakeFetch(json(201, SESSION));
    const api = createApiClient({ baseUrl: "/api", fetch });
    await api.register({ ...CREDS, admin: true } as typeof CREDS);
    expect(JSON.parse(calls[0]?.init.body as string)).toEqual(CREDS);
  });

  it("session() returns null on 401 without firing onUnauthorized", async () => {
    const onUnauthorized = vi.fn();
    const { fetch } = fakeFetch(errorJson(401, "AUTH_REQUIRED"));
    const api = createApiClient({ baseUrl: "/api", fetch, onUnauthorized });
    await expect(api.session()).resolves.toBeNull();
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("session() stores the CSRF token of an existing session", async () => {
    const { fetch } = fakeFetch(json(200, CURRENT));
    const api = createApiClient({ baseUrl: "/api", fetch });
    await expect(api.session()).resolves.toEqual(CURRENT);
    expect(api.csrfToken).toBe("csrf-1");
  });

  it("fires onUnauthorized when a signed-in session disappears", async () => {
    const onUnauthorized = vi.fn();
    const { fetch } = fakeFetch(json(200, SESSION), errorJson(401, "AUTH_REQUIRED"));
    const api = createApiClient({ baseUrl: "/api", fetch, onUnauthorized });
    await api.login(CREDS);
    await expect(api.logoutAll()).rejects.toMatchObject({ status: 401, code: "AUTH_REQUIRED" });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
    expect(api.csrfToken).toBeNull();
  });

  it("turns the API error body into an ApiError", async () => {
    const details = [{ path: "password", message: "must be at least 15 characters" }];
    const { fetch } = fakeFetch(errorJson(400, "VALIDATION_FAILED", { details }));
    const api = createApiClient({ baseUrl: "/api", fetch });
    const error = await api.register(CREDS).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      status: 400,
      code: "VALIDATION_FAILED",
      message: "VALIDATION_FAILED message",
      requestId: "req-9",
      details,
    });
  });

  it("reads Retry-After on 429", async () => {
    const response = errorJson(429, "RATE_LIMITED");
    response.headers.set("retry-after", "42");
    const { fetch } = fakeFetch(response);
    const api = createApiClient({ baseUrl: "/api", fetch });
    await expect(api.login(CREDS)).rejects.toMatchObject({ status: 429, retryAfterSeconds: 42 });
  });

  it("handles a non-JSON error page (e.g. a proxy's 502)", async () => {
    const { fetch } = fakeFetch(
      new Response("<html>Bad Gateway</html>", {
        status: 502,
        headers: { "content-type": "text/html", "x-request-id": "edge-1" },
      }),
    );
    const api = createApiClient({ baseUrl: "/api", fetch });
    await expect(api.health()).rejects.toMatchObject({
      status: 502,
      code: UNEXPECTED_RESPONSE,
      requestId: "edge-1",
    });
  });

  it("rejects a success response with the wrong shape", async () => {
    const { fetch } = fakeFetch(json(200, { user: { id: 1 }, csrfToken: "" }));
    const api = createApiClient({ baseUrl: "/api", fetch });
    const error = await api.login(CREDS).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiResponseError);
    expect(error).toMatchObject({ status: 200, path: "/auth/login" });
    expect(api.csrfToken).toBeNull();
  });

  it("rejects a success response that isn't JSON", async () => {
    const { fetch } = fakeFetch(new Response("ok", { headers: { "content-type": "text/plain" } }));
    const api = createApiClient({ baseUrl: "/api", fetch });
    await expect(api.health()).rejects.toBeInstanceOf(ApiResponseError);
  });

  it("rejects malformed JSON", async () => {
    const { fetch } = fakeFetch(
      new Response("{", { headers: { "content-type": "application/json" } }),
    );
    const api = createApiClient({ baseUrl: "/api", fetch });
    await expect(api.health()).rejects.toBeInstanceOf(ApiResponseError);
  });

  it("wraps network failures", async () => {
    const { fetch } = fakeFetch(new TypeError("fetch failed"));
    const api = createApiClient({ baseUrl: "/api", fetch });
    const error = await api.health().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiNetworkError);
    expect(error).toMatchObject({ timedOut: false });
  });

  it("times out", async () => {
    const fetch = ((_input: RequestInfo | URL, init: RequestInit = {}) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => {
          reject(init.signal?.reason as Error);
        });
      })) as typeof globalThis.fetch;
    const api = createApiClient({ baseUrl: "/api", fetch, timeoutMs: 20 });
    await expect(api.health()).rejects.toMatchObject({ name: "ApiNetworkError", timedOut: true });
  });

  it("lets a caller's abort through untouched", async () => {
    const fetch = ((_input: RequestInfo | URL, init: RequestInit = {}) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => {
          reject(init.signal?.reason as Error);
        });
      })) as typeof globalThis.fetch;
    const api = createApiClient({ baseUrl: "/api", fetch });
    const controller = new AbortController();
    const pending = api.health({ signal: controller.signal });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
  });

  it("retries once with a fresh token after CSRF_TOKEN_INVALID", async () => {
    const fresh = { ...CURRENT, csrfToken: "csrf-2" };
    const { fetch, calls } = fakeFetch(
      json(200, SESSION),
      errorJson(403, "CSRF_TOKEN_INVALID"),
      json(200, fresh),
      new Response(null, { status: 204 }),
    );
    const api = createApiClient({ baseUrl: "/api", fetch });
    await api.login(CREDS);
    await api.logoutAll();
    expect(calls.map((c) => `${String(c.init.method)} ${c.url}`)).toEqual([
      "POST /api/auth/login",
      "POST /api/auth/logout-all",
      "GET /api/auth/session",
      "POST /api/auth/logout-all",
    ]);
    expect(calls[1]?.headers.get(CSRF_HEADER)).toBe("csrf-1");
    expect(calls[3]?.headers.get(CSRF_HEADER)).toBe("csrf-2");
  });

  it("retries a CSRF failure only once", async () => {
    const { fetch, calls } = fakeFetch(
      json(200, SESSION),
      errorJson(403, "CSRF_TOKEN_INVALID"),
      json(200, CURRENT),
      errorJson(403, "CSRF_TOKEN_INVALID"),
    );
    const api = createApiClient({ baseUrl: "/api", fetch });
    await api.login(CREDS);
    await expect(api.logoutAll()).rejects.toMatchObject({ code: "CSRF_TOKEN_INVALID" });
    expect(calls).toHaveLength(4);
  });

  it("doesn't retry a CSRF failure once the session is gone", async () => {
    const { fetch, calls } = fakeFetch(
      json(200, SESSION),
      errorJson(403, "CSRF_TOKEN_INVALID"),
      errorJson(401, "AUTH_REQUIRED"),
    );
    const api = createApiClient({ baseUrl: "/api", fetch });
    await api.login(CREDS);
    await expect(api.logoutAll()).rejects.toMatchObject({ code: "CSRF_TOKEN_INVALID" });
    expect(calls).toHaveLength(3);
    expect(api.csrfToken).toBeNull();
  });

  it("joins an absolute base URL", async () => {
    const { fetch, calls } = fakeFetch(json(200, { status: "ok", uptimeSeconds: 0 }));
    const api = createApiClient({ baseUrl: "http://127.0.0.1:3001/", fetch });
    await api.health();
    expect(calls[0]?.url).toBe("http://127.0.0.1:3001/health");
  });
});

describe("isValidApiPath", () => {
  it.each(["/health", "/auth/session", "/sites/abc-123/scans?cursor=a%3D&limit=20", "/"])(
    "accepts %s",
    (path) => {
      expect(isValidApiPath(path)).toBe(true);
    },
  );

  it.each(["health", "//evil.example/x", "/a b", "/x#frag", "/x?a?b", "/x?a=<b>", "https://x/y"])(
    "rejects %s",
    (path) => {
      expect(isValidApiPath(path)).toBe(false);
    },
  );
});

describe("isJsonContentType", () => {
  it.each([
    "application/json",
    "application/json; charset=utf-8",
    "APPLICATION/JSON",
    "application/problem+json",
  ])("accepts %s", (value) => {
    expect(isJsonContentType(value)).toBe(true);
  });

  it.each([null, "", "text/html", "text/json", "application/jsonp", "application/json-seq"])(
    "rejects %s",
    (value) => {
      expect(isJsonContentType(value)).toBe(false);
    },
  );
});
