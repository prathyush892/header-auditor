/**
 * The typed client against the real API (in-memory stores) over a real
 * socket on 127.0.0.1. If the API's responses and the client's schemas drift
 * apart, this is the test that fails.
 *
 * Node's fetch has no cookie jar, so `browserLikeFetch` plays the browser:
 * it keeps the session cookie and sends `Origin` like a page on the
 * dashboard's origin would.
 */
import type { AddressInfo } from "node:net";

import {
  buildApp,
  createPasswordHasher,
  CSRF_HEADER as API_CSRF_HEADER,
  DEV_COOKIE_NAME,
  loadConfig,
  MemoryAuthStore,
  SECURE_COOKIE_NAME,
} from "@header-auditor/api";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ApiError, type ApiClient, createApiClient, CSRF_HEADER } from "@/lib/api";
import { SESSION_COOKIE_NAMES } from "@/lib/session-cookie";

const ORIGIN = "http://localhost:3000";
const PASSWORD = "correct horse battery staple";

interface Browser {
  readonly fetch: typeof fetch;
  readonly cookies: Map<string, string>;
}

function browserLikeFetch(origin: string | null = ORIGIN): Browser {
  const cookies = new Map<string, string>();
  const wrapped: typeof fetch = async (input, init = {}) => {
    const headers = new Headers(init.headers);
    if (cookies.size > 0) {
      headers.set("cookie", [...cookies].map(([k, v]) => `${k}=${v}`).join("; "));
    }
    if (origin !== null && init.method !== undefined && init.method !== "GET") {
      headers.set("origin", origin);
    }
    const response = await fetch(input, { ...init, headers });
    for (const line of response.headers.getSetCookie()) {
      const [pair = "", ...attributes] = line.split(";");
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expired = attributes.some((a) => /^\s*max-age=0\b/i.test(a)) || value === "";
      if (expired) cookies.delete(name);
      else cookies.set(name, value);
    }
    return response;
  };
  return { fetch: wrapped, cookies };
}

let app: Awaited<ReturnType<typeof buildApp>>;
let baseUrl: string;

beforeAll(async () => {
  app = await buildApp({
    config: loadConfig({
      NODE_ENV: "test",
      LOG_LEVEL: "silent",
      AUTH_COOKIE_SECURE: "false",
      API_ALLOWED_ORIGINS: ORIGIN,
    }),
    auth: {
      store: new MemoryAuthStore(),
      // Minimum argon2id cost: same code path, milliseconds per hash.
      hasher: createPasswordHasher({ memoryCost: 64, timeCost: 1, parallelism: 1 }),
      pruneIntervalMs: 0,
    },
  });
  await app.listen({ host: "127.0.0.1", port: 0 });
  baseUrl = `http://127.0.0.1:${String((app.server.address() as AddressInfo).port)}`;
});

afterAll(async () => {
  await app.close();
});

function client(browser: Browser): ApiClient {
  return createApiClient({ baseUrl, fetch: browser.fetch, timeoutMs: 5_000 });
}

let counter = 0;
function freshEmail(): string {
  counter += 1;
  return `user${String(counter)}@example.com`;
}

describe("client ↔ API contract", () => {
  it("uses the API's cookie names", () => {
    expect([...SESSION_COOKIE_NAMES].sort()).toEqual([SECURE_COOKIE_NAME, DEV_COOKIE_NAME].sort());
  });

  it("parses /health", async () => {
    const health = await client(browserLikeFetch()).health();
    expect(health.status).toBe("ok");
  });

  it("register → session → logout → signed out", async () => {
    const browser = browserLikeFetch();
    const api = client(browser);
    const email = freshEmail();

    const registered = await api.register({ email, password: PASSWORD });
    expect(registered.user.email).toBe(email);
    expect(browser.cookies.has(DEV_COOKIE_NAME)).toBe(true);
    expect(api.csrfToken).toBe(registered.csrfToken);

    const current = await api.session();
    expect(current?.user).toEqual(registered.user);
    expect(current?.csrfToken).toBe(registered.csrfToken);

    await api.logout();
    expect(browser.cookies.has(DEV_COOKIE_NAME)).toBe(false);
    await expect(api.session()).resolves.toBeNull();
  });

  it("a new tab (fresh client, same cookies) recovers the CSRF token from /auth/session", async () => {
    const browser = browserLikeFetch();
    const email = freshEmail();
    await client(browser).register({ email, password: PASSWORD });

    const secondTab = client(browser);
    expect(secondTab.csrfToken).toBeNull();
    await secondTab.session();
    await expect(secondTab.logoutAll()).resolves.toBeUndefined();
  });

  it("the API rejects an unsafe request without the CSRF token", async () => {
    const browser = browserLikeFetch();
    await client(browser).register({ email: freshEmail(), password: PASSWORD });
    const response = await browser.fetch(`${baseUrl}/auth/logout-all`, { method: "POST" });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("CSRF_TOKEN_INVALID");
  });

  it("recovers from a stale CSRF token after signing in again elsewhere", async () => {
    const browser = browserLikeFetch();
    const email = freshEmail();
    const tabA = client(browser);
    await tabA.register({ email, password: PASSWORD });
    const oldToken = tabA.csrfToken;

    // Tab B signs in again: new session cookie, so tab A's token is stale.
    const tabB = client(browser);
    await tabB.login({ email, password: PASSWORD });
    expect(tabB.csrfToken).not.toBe(oldToken);

    await expect(tabA.logoutAll()).resolves.toBeUndefined();
    await expect(tabB.session()).resolves.toBeNull();
  });

  it("maps the API's error codes", async () => {
    const api = client(browserLikeFetch());
    const email = freshEmail();
    await api.register({ email, password: PASSWORD });

    const other = client(browserLikeFetch());
    await expect(other.register({ email, password: PASSWORD })).rejects.toMatchObject({
      status: 409,
      code: "EMAIL_TAKEN",
    });
    await expect(other.login({ email, password: "wrong password entirely" })).rejects.toMatchObject(
      { status: 401, code: "INVALID_CREDENTIALS" },
    );
    const weak: unknown = await other
      .register({ email: freshEmail(), password: "short" })
      .catch((error: unknown) => error);
    expect(weak).toBeInstanceOf(ApiError);
    expect(weak).toMatchObject({ status: 400, code: "VALIDATION_FAILED" });
    expect((weak as ApiError).details.map((d) => d.path)).toContain("password");
    expect((weak as ApiError).requestId).not.toBeNull();
  });

  it("the API refuses a request from a foreign origin", async () => {
    const api = client(browserLikeFetch("https://evil.example"));
    await expect(api.login({ email: freshEmail(), password: PASSWORD })).rejects.toMatchObject({
      status: 403,
      code: "CSRF_ORIGIN_REJECTED",
    });
  });

  it("logout without a session is a no-op 204", async () => {
    await expect(client(browserLikeFetch()).logout()).resolves.toBeUndefined();
  });

  it("logoutAll without a session is a 401", async () => {
    await expect(client(browserLikeFetch()).logoutAll()).rejects.toMatchObject({
      status: 401,
      code: "AUTH_REQUIRED",
    });
  });

  it("sends the token in the header the API reads", () => {
    expect(CSRF_HEADER).toBe(API_CSRF_HEADER);
  });
});
