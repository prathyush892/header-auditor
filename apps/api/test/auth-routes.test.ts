/**
 * Auth over the full Fastify lifecycle (app.inject): cookies, CSRF, rate
 * limits, session expiry and what ends up in the logs.
 */
import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createPasswordHasher } from "../src/auth/password.js";
import {
  CSRF_HEADER,
  DEV_COOKIE_NAME,
  requireAuth,
  SECURE_COOKIE_NAME,
  TOUCH_INTERVAL_MS,
} from "../src/auth/plugin.js";
import { MemoryAuthStore } from "../src/auth/store.js";
import { hashSessionToken } from "../src/auth/tokens.js";
import type { Env } from "../src/config.js";
import { createTestApp, type LogCapture } from "./helpers/app.js";
import {
  FAST_ARGON2,
  fastHasher,
  login,
  ORIGIN,
  PASSWORD,
  register,
  sessionFrom,
  setCookieHeaders,
  TestClock,
} from "./helpers/auth.js";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

interface Harness {
  readonly app: FastifyInstance;
  readonly store: MemoryAuthStore;
  readonly clock: TestClock;
  readonly logs: LogCapture;
}

let current: Harness | undefined;

afterEach(async () => {
  await current?.app.close();
  current = undefined;
});

async function harness(
  env: Env = {},
  overrides: { hasher?: ReturnType<typeof fastHasher>; pruneIntervalMs?: number } = {},
): Promise<Harness> {
  const store = new MemoryAuthStore();
  const clock = new TestClock();
  const { app, logs } = await createTestApp({
    env: { AUTH_SESSION_IDLE_MINUTES: "30", AUTH_SESSION_TTL_HOURS: "8", ...env },
    auth: {
      store,
      hasher: overrides.hasher ?? fastHasher(),
      now: clock.now,
      pruneIntervalMs: overrides.pruneIntervalMs ?? 0,
    },
    setup(instance) {
      instance.post("/test/protected", (request) => ({ userId: requireAuth(request).user.id }));
      instance.get("/test/whoami", (request) => ({ userId: request.auth?.user.id ?? null }));
    },
  });
  current = { app, store, clock, logs };
  return current;
}

function getSession(app: FastifyInstance, cookie?: string) {
  return app.inject({
    method: "GET",
    url: "/auth/session",
    headers: cookie === undefined ? {} : { cookie },
  });
}

function post(
  app: FastifyInstance,
  url: string,
  headers: Record<string, string>,
  payload?: unknown,
) {
  return app.inject({
    method: "POST",
    url,
    headers: { origin: ORIGIN, ...headers },
    ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
  });
}

describe("POST /auth/register", () => {
  it("creates the user, starts a session and sets a hardened cookie", async () => {
    const { app, store } = await harness();
    const response = await register(app, "  New.User@Example.TEST ");
    expect(response.statusCode).toBe(201);

    const body = response.json<{
      user: { id: string; email: string; createdAt: string };
      csrfToken: string;
      expiresAt: string;
    }>();
    expect(Object.keys(body).sort()).toEqual(["csrfToken", "expiresAt", "user"]);
    expect(Object.keys(body.user).sort()).toEqual(["createdAt", "email", "id"]);
    expect(body.user.email).toBe("new.user@example.test");
    expect(body.user.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(body.csrfToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(body.expiresAt).toBe("2026-11-22T20:00:00.000Z");
    expect(response.body).not.toMatch(/argon2|passwordHash/);

    const [cookie] = setCookieHeaders(response);
    expect(cookie?.startsWith(`${SECURE_COOKIE_NAME}=`)).toBe(true);
    expect(cookie).toMatch(/^[^=]+=[A-Za-z0-9_-]{43};/);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain(`Max-Age=${String(8 * 3600)}`);
    expect(cookie).not.toMatch(/Domain=/i);

    const token = (cookie ?? "").split(";")[0]?.split("=")[1] ?? "";
    const [stored] = store.allSessions();
    expect(stored?.tokenHash).toBe(hashSessionToken(token));
    expect(JSON.stringify(store.allSessions())).not.toContain(token);
    const user = await store.findUserByEmail("new.user@example.test");
    expect(user?.passwordHash).toMatch(/^\$argon2id\$/);
  });

  it("uses a non-__Host- cookie without Secure when AUTH_COOKIE_SECURE=false", async () => {
    const { app } = await harness({ AUTH_COOKIE_SECURE: "false" });
    const [cookie] = setCookieHeaders(await register(app, "dev@example.test"));
    expect(cookie?.startsWith(`${DEV_COOKIE_NAME}=`)).toBe(true);
    expect(cookie).not.toContain("Secure");
    expect(cookie).toContain("HttpOnly");
  });

  it("rejects a duplicate email regardless of case", async () => {
    const { app } = await harness();
    await register(app, "dup@example.test");
    const response = await register(app, "DUP@example.test");
    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: "EMAIL_TAKEN" } });
    expect(setCookieHeaders(response)).toEqual([]);
  });

  it.each([
    ["too short", "short-pass", /at least 15/],
    ["the email itself", "weak.person@example.test", /email address/],
    ["one repeated character", "x".repeat(20), /repeated/],
  ])("rejects a password that is %s", async (_label, password, message) => {
    const { app, store } = await harness();
    const response = await register(app, "weak.person@example.test", password);
    expect(response.statusCode).toBe(400);
    const body = response.json<{
      error: { code: string; details: { path: string; message: string }[] };
    }>();
    expect(body.error.code).toBe("VALIDATION_FAILED");
    expect(body.error.details[0]?.path).toBe("password");
    expect(body.error.details[0]?.message).toMatch(message);
    expect(await store.findUserByEmail("weak.person@example.test")).toBeNull();
    expect(response.body).not.toContain(password);
  });

  it.each([
    ["invalid email", { email: "not-an-email", password: PASSWORD }, "email"],
    ["missing password", { email: "a@example.test" }, "password"],
    ["unknown field", { email: "a@example.test", password: PASSWORD, admin: true }, "<root>"],
    ["oversized email", { email: `${"a".repeat(250)}@example.test`, password: PASSWORD }, "email"],
  ])("rejects %s with 400", async (_label, payload, path) => {
    const { app } = await harness();
    const response = await post(app, "/auth/register", {}, payload);
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: { code: "VALIDATION_FAILED", details: [expect.objectContaining({ path })] },
    });
  });

  it("is rate limited per IP", async () => {
    const { app } = await harness({ AUTH_RATE_LIMIT_PER_IP: "2" });
    expect((await register(app, "r1@example.test")).statusCode).toBe(201);
    expect((await register(app, "r2@example.test")).statusCode).toBe(201);
    const blocked = await register(app, "r3@example.test");
    expect(blocked.statusCode).toBe(429);
    expect(blocked.headers["retry-after"]).toBe("900");
  });
});

describe("POST /auth/login", () => {
  it("signs in with the right password, case-insensitively, and issues a new session", async () => {
    const { app, store } = await harness();
    const first = sessionFrom(await register(app, "login@example.test"));
    const response = await login(app, "LOGIN@example.test");
    expect(response.statusCode).toBe(200);
    const second = sessionFrom(response);
    expect(second.cookie).not.toBe(first.cookie);
    expect(second.csrfToken).not.toBe(first.csrfToken);
    expect(store.allSessions()).toHaveLength(2);
  });

  it("gives the same answer for an unknown email and a wrong password", async () => {
    const hasher = fastHasher();
    const burn = vi.spyOn(hasher, "burn");
    const { app } = await harness({}, { hasher });
    await register(app, "known@example.test");

    const wrong = await login(app, "known@example.test", "wrong password, long enough");
    const unknown = await login(app, "unknown@example.test");
    for (const response of [wrong, unknown]) {
      expect(response.statusCode).toBe(401);
      expect(setCookieHeaders(response)).toEqual([]);
    }
    const strip = (body: string): Record<string, unknown> => {
      const parsed = JSON.parse(body) as { error: Record<string, unknown> };
      return { ...parsed.error, requestId: undefined };
    };
    expect(strip(wrong.body)).toEqual(strip(unknown.body));
    expect(strip(wrong.body)).toMatchObject({
      code: "INVALID_CREDENTIALS",
      message: "Invalid email or password",
    });
    // Unknown users still pay for an argon2 verification (no timing oracle).
    expect(burn).toHaveBeenCalledTimes(1);
  });

  it("locks one account after too many attempts, even from different IPs", async () => {
    const { app } = await harness({ AUTH_RATE_LIMIT_PER_ACCOUNT: "3" });
    await register(app, "target@example.test");
    for (let i = 0; i < 3; i += 1) {
      const response = await app.inject({
        method: "POST",
        url: "/auth/login",
        remoteAddress: `198.51.100.${String(i + 1)}`,
        headers: { origin: ORIGIN },
        payload: { email: "target@example.test", password: `guess number ${String(i)} xx` },
      });
      expect(response.statusCode).toBe(401);
    }
    // Even the correct password is refused while the account is throttled.
    const blocked = await login(app, "target@example.test", PASSWORD, {});
    expect(blocked.statusCode).toBe(429);
    expect(blocked.json()).toMatchObject({ error: { code: "RATE_LIMITED" } });
    expect(Number(blocked.headers["retry-after"])).toBeGreaterThan(0);
    // Other accounts are unaffected.
    await register(app, "other@example.test");
    expect((await login(app, "other@example.test")).statusCode).toBe(200);
  });

  it("limits one IP spraying many accounts", async () => {
    const { app } = await harness({ AUTH_RATE_LIMIT_PER_IP: "4" });
    const statuses: number[] = [];
    for (let i = 0; i < 6; i += 1) {
      statuses.push((await login(app, `spray${String(i)}@example.test`)).statusCode);
    }
    expect(statuses).toEqual([401, 401, 401, 401, 429, 429]);
    const elsewhere = await app.inject({
      method: "POST",
      url: "/auth/login",
      remoteAddress: "203.0.113.9",
      headers: { origin: ORIGIN },
      payload: { email: "spray9@example.test", password: PASSWORD },
    });
    expect(elsewhere.statusCode).toBe(401);
  });

  it("resets the account counter after a successful login", async () => {
    const { app } = await harness({ AUTH_RATE_LIMIT_PER_ACCOUNT: "2" });
    await register(app, "reset@example.test");
    expect((await login(app, "reset@example.test", "typo typo typo typo")).statusCode).toBe(401);
    expect((await login(app, "reset@example.test")).statusCode).toBe(200);
    expect((await login(app, "reset@example.test", "typo typo typo typo")).statusCode).toBe(401);
    expect((await login(app, "reset@example.test")).statusCode).toBe(200);
  });

  it("re-hashes a password stored with outdated parameters", async () => {
    const { app, store } = await harness(
      {},
      { hasher: createPasswordHasher({ ...FAST_ARGON2, timeCost: 2 }) },
    );
    const old = await store.createUser("legacy@example.test", await fastHasher().hash(PASSWORD));
    expect(old.passwordHash).toContain("t=1");
    expect((await login(app, "legacy@example.test")).statusCode).toBe(200);
    expect((await store.findUserById(old.id))?.passwordHash).toContain("t=2");
  });

  it("replaces the session the request arrived with (no session fixation)", async () => {
    const { app, store } = await harness();
    const before = sessionFrom(await register(app, "fixation@example.test"));
    const response = await login(app, "fixation@example.test", PASSWORD, { cookie: before.cookie });
    expect(response.statusCode).toBe(200);
    expect(store.allSessions()).toHaveLength(1);
    expect((await getSession(app, before.cookie)).statusCode).toBe(401);
    expect((await getSession(app, sessionFrom(response).cookie)).statusCode).toBe(200);
  });

  it("never logs passwords, cookies, tokens or email addresses", async () => {
    const { app, logs } = await harness();
    const session = sessionFrom(await register(app, "secret.person@example.test"));
    await login(app, "secret.person@example.test", "a wrong password that is long");
    await login(app, "secret.person@example.test", PASSWORD, { cookie: session.cookie });
    const text = logs.text();
    expect(text).not.toContain(PASSWORD);
    expect(text).not.toContain("a wrong password");
    expect(text).not.toContain(session.cookie.split("=")[1]);
    expect(text).not.toContain(session.csrfToken);
    expect(text).not.toContain("secret.person");
    expect(logs.lines.some((l) => l.msg === "login failed")).toBe(true);
    expect(logs.lines.some((l) => l.msg === "session started")).toBe(true);
  });
});

describe("GET /auth/session", () => {
  it("returns the user and CSRF token for a valid cookie", async () => {
    const { app } = await harness();
    const session = sessionFrom(await register(app, "me@example.test"));
    const response = await getSession(app, session.cookie);
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      user: session.body.user,
      csrfToken: session.csrfToken,
      expiresAt: "2026-11-22T20:00:00.000Z",
      idleExpiresAt: "2026-11-22T12:30:00.000Z",
    });
    expect(response.headers["cache-control"]).toBe("no-store");
  });

  it.each([
    ["no cookie", undefined],
    ["a malformed cookie", `${SECURE_COOKIE_NAME}=../../etc/passwd`],
    ["an unknown token", `${SECURE_COOKIE_NAME}=${"A".repeat(43)}`],
  ])("returns 401 for %s", async (_label, cookie) => {
    const { app } = await harness();
    const response = await getSession(app, cookie);
    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ error: { code: "AUTH_REQUIRED" } });
    if (cookie !== undefined)
      expect(setCookieHeaders(response)[0]).toMatch(/Max-Age=0|Expires=Thu, 01 Jan 1970/);
  });

  it("slides the idle deadline on use, but only writes lastSeenAt once a minute", async () => {
    const { app, store, clock } = await harness();
    const session = sessionFrom(await register(app, "idle@example.test"));
    const touch = vi.spyOn(store, "touchSession");

    clock.advance(TOUCH_INTERVAL_MS - 1);
    expect((await getSession(app, session.cookie)).statusCode).toBe(200);
    expect(touch).not.toHaveBeenCalled();

    // Active every 20 minutes for 2 hours: never idle for 30.
    for (let i = 0; i < 6; i += 1) {
      clock.advance(20 * MINUTE);
      expect((await getSession(app, session.cookie)).statusCode).toBe(200);
    }
    expect(touch).toHaveBeenCalledTimes(6);
  });

  it("expires a session left idle, and deletes it", async () => {
    const { app, store, clock } = await harness();
    const session = sessionFrom(await register(app, "away@example.test"));
    clock.advance(30 * MINUTE);
    expect((await getSession(app, session.cookie)).statusCode).toBe(401);
    expect(store.allSessions()).toHaveLength(0);
  });

  it("expires a session at its absolute lifetime even if it is in constant use", async () => {
    const { app, clock } = await harness();
    const session = sessionFrom(await register(app, "busy@example.test"));
    for (let elapsed = 0; elapsed < 8 * HOUR - 10 * MINUTE; elapsed += 10 * MINUTE) {
      clock.advance(10 * MINUTE);
      expect((await getSession(app, session.cookie)).statusCode).toBe(200);
    }
    clock.advance(10 * MINUTE);
    expect((await getSession(app, session.cookie)).statusCode).toBe(401);
  });

  it("drops a session whose user no longer exists", async () => {
    const { app, store } = await harness();
    const session = sessionFrom(await register(app, "gone@example.test"));
    vi.spyOn(store, "findUserById").mockResolvedValue(null);
    expect((await getSession(app, session.cookie)).statusCode).toBe(401);
    expect(store.allSessions()).toHaveLength(0);
  });
});

describe("CSRF protection", () => {
  it("requires the session's CSRF token on authenticated unsafe requests", async () => {
    const { app } = await harness();
    const alice = sessionFrom(await register(app, "alice@example.test"));
    const bob = sessionFrom(await register(app, "bob@example.test"));

    const missing = await post(app, "/test/protected", { cookie: alice.cookie });
    expect(missing.statusCode).toBe(403);
    expect(missing.json()).toMatchObject({ error: { code: "CSRF_TOKEN_INVALID" } });

    const someoneElses = await post(app, "/test/protected", {
      cookie: alice.cookie,
      [CSRF_HEADER]: bob.csrfToken,
    });
    expect(someoneElses.statusCode).toBe(403);

    const ok = await post(app, "/test/protected", {
      cookie: alice.cookie,
      [CSRF_HEADER]: alice.csrfToken,
    });
    expect(ok.statusCode).toBe(200);
    expect(ok.json()).toEqual({ userId: (alice.body.user as { id: string }).id });
  });

  it("does not require a token for safe methods", async () => {
    const { app } = await harness();
    const session = sessionFrom(await register(app, "reader@example.test"));
    const response = await app.inject({
      method: "GET",
      url: "/test/whoami",
      headers: { cookie: session.cookie },
    });
    expect(response.statusCode).toBe(200);
  });

  it.each([
    ["a foreign Origin", { origin: "https://evil.example" }],
    ["Origin: null (sandboxed iframe, file://)", { origin: "null" }],
    ["a look-alike Origin", { origin: "http://localhost:3000.evil.example" }],
    ["Sec-Fetch-Site: cross-site without Origin", { origin: "", "sec-fetch-site": "cross-site" }],
    ["Sec-Fetch-Site: same-site without Origin", { origin: "", "sec-fetch-site": "same-site" }],
  ])("rejects login from %s", async (_label, headers) => {
    const { app } = await harness();
    await register(app, "victim@example.test");
    const clean = Object.fromEntries(Object.entries(headers).filter(([, v]) => v !== ""));
    const response = await app.inject({
      method: "POST",
      url: "/auth/login",
      headers: clean,
      payload: { email: "victim@example.test", password: PASSWORD },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: { code: "CSRF_ORIGIN_REJECTED" } });
    expect(setCookieHeaders(response)).toEqual([]);
  });

  it("accepts non-browser clients that send no Origin and no Sec-Fetch-Site", async () => {
    const { app } = await harness();
    await register(app, "cli@example.test");
    const response = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: { email: "cli@example.test", password: PASSWORD },
    });
    expect(response.statusCode).toBe(200);
  });

  it.each([
    ["text/plain", JSON.stringify({ email: "a@example.test", password: PASSWORD })],
    [
      "application/x-www-form-urlencoded",
      `email=a%40example.test&password=${encodeURIComponent(PASSWORD)}`,
    ],
    ["multipart/form-data; boundary=x", "--x\r\n\r\n--x--"],
  ])("refuses %s bodies (what a cross-site form can send) with 415", async (type, payload) => {
    const { app } = await harness();
    const response = await app.inject({
      method: "POST",
      url: "/auth/register",
      headers: { origin: ORIGIN, "content-type": type },
      payload,
    });
    expect(response.statusCode).toBe(415);
  });
});

describe("logout", () => {
  it("ends the session and clears the cookie", async () => {
    const { app, store } = await harness();
    const session = sessionFrom(await register(app, "bye@example.test"));
    const response = await post(app, "/auth/logout", {
      cookie: session.cookie,
      [CSRF_HEADER]: session.csrfToken,
    });
    expect(response.statusCode).toBe(204);
    expect(setCookieHeaders(response)[0]?.startsWith(`${SECURE_COOKIE_NAME}=;`)).toBe(true);
    expect(store.allSessions()).toHaveLength(0);
    expect((await getSession(app, session.cookie)).statusCode).toBe(401);
  });

  it("can't be triggered cross-site: no CSRF token, no logout", async () => {
    const { app } = await harness();
    const session = sessionFrom(await register(app, "stay@example.test"));
    const response = await post(app, "/auth/logout", { cookie: session.cookie });
    expect(response.statusCode).toBe(403);
    expect((await getSession(app, session.cookie)).statusCode).toBe(200);
  });

  it("is a harmless 204 without a session", async () => {
    const { app } = await harness();
    expect((await post(app, "/auth/logout", {})).statusCode).toBe(204);
  });

  it("logout-all ends every session of the user and nobody else's", async () => {
    const { app } = await harness();
    const laptop = sessionFrom(await register(app, "multi@example.test"));
    const phone = sessionFrom(await login(app, "multi@example.test"));
    const other = sessionFrom(await register(app, "someone@example.test"));

    const response = await post(app, "/auth/logout-all", {
      cookie: phone.cookie,
      [CSRF_HEADER]: phone.csrfToken,
    });
    expect(response.statusCode).toBe(204);
    expect((await getSession(app, laptop.cookie)).statusCode).toBe(401);
    expect((await getSession(app, phone.cookie)).statusCode).toBe(401);
    expect((await getSession(app, other.cookie)).statusCode).toBe(200);
  });

  it("logout-all requires a session", async () => {
    const { app } = await harness();
    const response = await post(app, "/auth/logout-all", {});
    expect(response.statusCode).toBe(401);
  });
});

describe("integration with the skeleton", () => {
  it("keeps health probes and security headers working", async () => {
    const { app } = await harness();
    const response = await app.inject({ method: "GET", url: "/health" });
    expect(response.statusCode).toBe(200);
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("prunes expired sessions in the background", async () => {
    const store = new MemoryAuthStore();
    const clock = new TestClock();
    const { app } = await createTestApp({
      env: { AUTH_SESSION_IDLE_MINUTES: "30" },
      auth: { store, hasher: fastHasher(), now: clock.now, pruneIntervalMs: 10 },
    });
    current = { app, store, clock, logs: undefined as unknown as LogCapture };
    await register(app, "prune@example.test");
    expect(store.allSessions()).toHaveLength(1);
    clock.advance(31 * MINUTE);
    await vi.waitFor(() => {
      expect(store.allSessions()).toHaveLength(0);
    });
  });
});
