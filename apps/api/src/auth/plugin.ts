/**
 * Auth for the API: registration, login, logout and session lookup, plus the
 * two request hooks every route gets.
 *
 *   onRequest   1. CSRF origin check for unsafe methods (Origin / Sec-Fetch-Site)
 *               2. Resolve the session cookie into `request.auth`
 *   preHandler  3. CSRF token check for unsafe methods when a session exists
 *
 * Routes call `requireAuth(request)` to get the signed-in user or a 401.
 */
import fastifyCookie from "@fastify/cookie";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";

import type { ApiConfig } from "../config.js";
import { AppError } from "../errors.js";
import {
  createPasswordHasher,
  PASSWORD_MAX_LENGTH,
  type PasswordHasher,
  passwordProblems,
} from "./password.js";
import { MemoryRateLimiter, type RateLimitDecision, type RateLimiter } from "./rate-limit.js";
import {
  type AuthStore,
  EmailTakenError,
  isSessionExpired,
  type SessionRecord,
  type UserRecord,
} from "./store.js";
import {
  deriveCsrfToken,
  generateSessionToken,
  hashSessionToken,
  isWellFormedSessionToken,
  verifyCsrfToken,
} from "./tokens.js";

export interface PublicUser {
  readonly id: string;
  readonly email: string;
  readonly createdAt: string;
}

/** Body of a successful register/login. */
export interface SessionResponse {
  readonly user: PublicUser;
  readonly csrfToken: string;
  readonly expiresAt: string;
}

export interface AuthContext {
  readonly user: PublicUser;
  readonly session: SessionRecord;
  /** Echo this in the `x-csrf-token` header on POST/PUT/PATCH/DELETE. */
  readonly csrfToken: string;
}

declare module "fastify" {
  interface FastifyRequest {
    /** Signed-in user for this request, or null. Set by the auth onRequest hook. */
    auth: AuthContext | null;
    /** Raw session token from the cookie, kept off `auth` so it is never serialised. */
    sessionToken: string | null;
  }
  interface FastifyContextConfig {
    /** Set to false on routes that must work without a CSRF token (login, register). */
    csrf?: boolean;
  }
}

export interface AuthOptions {
  readonly store: AuthStore;
  /** Defaults to argon2id with OWASP parameters. Tests inject cheaper ones. */
  readonly hasher?: PasswordHasher;
  /** Defaults to an in-process limiter using the configured window. */
  readonly rateLimiter?: RateLimiter;
  readonly now?: () => Date;
  /** How often expired sessions are deleted; 0 disables (default 1 hour). */
  readonly pruneIntervalMs?: number;
}

export const CSRF_HEADER = "x-csrf-token";
export const SECURE_COOKIE_NAME = "__Host-ha_session";
export const DEV_COOKIE_NAME = "ha_session";
/** `lastSeenAt` is written at most this often, so reads don't each cost a write. */
export const TOUCH_INTERVAL_MS = 60_000;
export const DEFAULT_PRUNE_INTERVAL_MS = 3_600_000;
const USER_AGENT_MAX_LENGTH = 255;
const LOGIN_PASSWORD_MAX_LENGTH = 1_024;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * `__Host-` tells the browser the cookie must be Secure, Path=/ and have no
 * Domain, so a sibling subdomain can't overwrite it (cookie tossing). Browsers
 * reject `__Host-` cookies without Secure, hence the plain name for http dev.
 */
export function sessionCookieName(secure: boolean): string {
  return secure ? SECURE_COOKIE_NAME : DEV_COOKIE_NAME;
}

const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(254, "must be at most 254 characters")
  .pipe(z.email("must be a valid email address"));

const registerBody = z.strictObject({
  email: emailSchema,
  password: z.string().max(PASSWORD_MAX_LENGTH * 4, "is too long"),
});

/** Login doesn't apply the policy (old passwords must still work), only a size cap. */
const loginBody = z.strictObject({
  email: emailSchema,
  password: z.string().min(1, "is required").max(LOGIN_PASSWORD_MAX_LENGTH, "is too long"),
});

export function toPublicUser(user: UserRecord): PublicUser {
  return { id: user.id, email: user.email, createdAt: user.createdAt.toISOString() };
}

/** Throws 401 unless the request carries a valid session. */
export function requireAuth(request: FastifyRequest): AuthContext {
  if (request.auth === null) {
    throw new AppError(401, "AUTH_REQUIRED", "Sign in to continue");
  }
  return request.auth;
}

/** Truncated, control-character-free User-Agent for the session list. */
export function sanitizeUserAgent(value: string | undefined): string | null {
  if (value === undefined) return null;
  // eslint-disable-next-line no-control-regex
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  return cleaned === "" ? null : cleaned.slice(0, USER_AGENT_MAX_LENGTH);
}

/**
 * Decides whether an unsafe request may come from where it says it came from.
 * Browsers send `Origin` on every cross-origin (and modern same-origin) POST;
 * `Sec-Fetch-Site` is the fallback. Requests with neither are not from a
 * browser page, and therefore not a CSRF vector (curl, server-to-server).
 */
export function isTrustedOrigin(
  headers: FastifyRequest["headers"],
  allowedOrigins: readonly string[],
): boolean {
  const origin = headers.origin;
  if (typeof origin === "string") return allowedOrigins.includes(origin);
  const site = headers["sec-fetch-site"];
  if (typeof site === "string") return site === "same-origin" || site === "none";
  return true;
}

function retryAfterSeconds(decisions: readonly RateLimitDecision[]): number {
  const blocked = decisions.filter((d) => !d.allowed).map((d) => d.retryAfterMs);
  return Math.max(1, Math.ceil(Math.max(...blocked) / 1_000));
}

function rateLimited(reply: FastifyReply, decisions: readonly RateLimitDecision[]): AppError {
  void reply.header("retry-after", String(retryAfterSeconds(decisions)));
  return new AppError(429, "RATE_LIMITED", "Too many attempts. Try again later.");
}

export async function registerAuth(
  app: FastifyInstance,
  config: ApiConfig,
  options: AuthOptions,
): Promise<void> {
  const { store } = options;
  const auth = config.auth;
  const hasher = options.hasher ?? createPasswordHasher();
  const limiter =
    options.rateLimiter ?? new MemoryRateLimiter({ windowMs: auth.rateLimit.windowMs });
  const now = options.now ?? (() => new Date());
  const cookieName = sessionCookieName(auth.cookieSecure);
  const cookieOptions = {
    httpOnly: true,
    secure: auth.cookieSecure,
    sameSite: "lax",
    path: "/",
  } as const;

  await app.register(fastifyCookie);
  app.decorateRequest("auth", null);
  app.decorateRequest("sessionToken", null);

  function setSessionCookie(reply: FastifyReply, token: string): void {
    void reply.setCookie(cookieName, token, {
      ...cookieOptions,
      maxAge: Math.floor(auth.sessionTtlMs / 1_000),
    });
  }

  function clearSessionCookie(reply: FastifyReply): void {
    void reply.clearCookie(cookieName, cookieOptions);
  }

  async function resolveSession(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    // cookieName is one of two constants, not user input.
    // eslint-disable-next-line security/detect-object-injection
    const cookieValue = request.cookies[cookieName];
    if (cookieValue === undefined) return;
    if (!isWellFormedSessionToken(cookieValue)) {
      clearSessionCookie(reply);
      return;
    }
    const session = await store.findSessionByTokenHash(hashSessionToken(cookieValue));
    const at = now();
    if (session === null || isSessionExpired(session, at, auth.sessionIdleMs)) {
      if (session !== null) await store.deleteSession(session.id);
      clearSessionCookie(reply);
      return;
    }
    const user = await store.findUserById(session.userId);
    if (user === null) {
      await store.deleteSession(session.id);
      clearSessionCookie(reply);
      return;
    }
    let current = session;
    if (at.getTime() - session.lastSeenAt.getTime() >= TOUCH_INTERVAL_MS) {
      await store.touchSession(session.id, at);
      current = { ...session, lastSeenAt: at };
    }
    request.sessionToken = cookieValue;
    request.auth = {
      user: toPublicUser(user),
      session: current,
      csrfToken: deriveCsrfToken(cookieValue),
    };
  }

  app.addHook("onRequest", async (request, reply) => {
    if (
      !SAFE_METHODS.has(request.method) &&
      !isTrustedOrigin(request.headers, config.allowedOrigins)
    ) {
      throw new AppError(403, "CSRF_ORIGIN_REJECTED", "Request origin is not allowed");
    }
    await resolveSession(request, reply);
  });

  app.addHook("preHandler", (request, _reply, done) => {
    const { sessionToken } = request;
    const exempt =
      SAFE_METHODS.has(request.method) ||
      sessionToken === null ||
      request.routeOptions.config.csrf === false;
    if (exempt || verifyCsrfToken(sessionToken, request.headers["x-csrf-token"])) {
      done();
      return;
    }
    done(new AppError(403, "CSRF_TOKEN_INVALID", "Missing or invalid CSRF token"));
  });

  /** New session for `user`, replacing whatever session the request came with. */
  async function startSession(
    request: FastifyRequest,
    reply: FastifyReply,
    user: UserRecord,
  ): Promise<SessionResponse> {
    // Session fixation: never keep a token that existed before authentication.
    if (request.auth !== null) await store.deleteSession(request.auth.session.id);
    const token = generateSessionToken();
    const createdAt = now();
    const session = await store.createSession({
      userId: user.id,
      tokenHash: hashSessionToken(token),
      createdAt,
      expiresAt: new Date(createdAt.getTime() + auth.sessionTtlMs),
      userAgent: sanitizeUserAgent(request.headers["user-agent"]),
    });
    setSessionCookie(reply, token);
    request.log.info({ userId: user.id, sessionId: session.id }, "session started");
    return {
      user: toPublicUser(user),
      csrfToken: deriveCsrfToken(token),
      expiresAt: session.expiresAt.toISOString(),
    };
  }

  app.post("/auth/register", { config: { csrf: false } }, async (request, reply) => {
    const ipDecision = await limiter.consume(`register:ip:${request.ip}`, auth.rateLimit.perIp);
    if (!ipDecision.allowed) throw rateLimited(reply, [ipDecision]);

    const { email, password } = registerBody.parse(request.body);
    const problems = passwordProblems(password, email);
    if (problems.length > 0) {
      throw new AppError(400, "VALIDATION_FAILED", "Request validation failed", {
        details: problems.map((message) => ({ path: "password", message })),
      });
    }
    let user: UserRecord;
    try {
      user = await store.createUser(email, await hasher.hash(password));
    } catch (error) {
      if (error instanceof EmailTakenError) {
        throw new AppError(409, "EMAIL_TAKEN", "An account with this email already exists");
      }
      throw error;
    }
    return reply.status(201).send(await startSession(request, reply, user));
  });

  app.post("/auth/login", { config: { csrf: false } }, async (request, reply) => {
    const { email, password } = loginBody.parse(request.body);
    const accountKey = `login:account:${email}`;
    const decisions = await Promise.all([
      limiter.consume(`login:ip:${request.ip}`, auth.rateLimit.perIp),
      limiter.consume(accountKey, auth.rateLimit.perAccount),
    ]);
    if (decisions.some((d) => !d.allowed)) {
      request.log.warn({ reason: "rate_limited" }, "login blocked");
      throw rateLimited(reply, decisions);
    }

    const user = await store.findUserByEmail(email);
    let valid = false;
    if (user === null) await hasher.burn(password);
    else valid = await hasher.verify(user.passwordHash, password);
    if (user === null || !valid) {
      // Same status, code and message for "no such user" and "wrong password".
      request.log.info({ reason: "invalid_credentials" }, "login failed");
      throw new AppError(401, "INVALID_CREDENTIALS", "Invalid email or password");
    }

    await limiter.reset(accountKey);
    if (hasher.needsRehash(user.passwordHash)) {
      try {
        await store.updatePasswordHash(user.id, await hasher.hash(password));
      } catch (error) {
        // Upgrading the hash is best-effort; the login itself succeeded.
        request.log.error({ err: error, userId: user.id }, "password rehash failed");
      }
    }
    return reply.send(await startSession(request, reply, user));
  });

  app.post("/auth/logout", async (request, reply) => {
    if (request.auth !== null) {
      await store.deleteSession(request.auth.session.id);
      request.log.info({ userId: request.auth.user.id }, "session ended");
    }
    clearSessionCookie(reply);
    return reply.status(204).send();
  });

  app.post("/auth/logout-all", async (request, reply) => {
    const { user } = requireAuth(request);
    const ended = await store.deleteUserSessions(user.id);
    request.log.info({ userId: user.id, ended }, "all sessions ended");
    clearSessionCookie(reply);
    return reply.status(204).send();
  });

  app.get("/auth/session", (request) => {
    const { user, session, csrfToken } = requireAuth(request);
    return {
      user,
      csrfToken,
      expiresAt: session.expiresAt.toISOString(),
      idleExpiresAt: new Date(session.lastSeenAt.getTime() + auth.sessionIdleMs).toISOString(),
    };
  });

  const pruneIntervalMs = options.pruneIntervalMs ?? DEFAULT_PRUNE_INTERVAL_MS;
  if (pruneIntervalMs > 0) {
    const timer = setInterval(() => {
      store.deleteExpiredSessions(now(), auth.sessionIdleMs).then(
        (removed) => {
          if (removed > 0) app.log.info({ removed }, "pruned expired sessions");
        },
        (error: unknown) => {
          app.log.error({ err: error }, "session prune failed");
        },
      );
    }, pruneIntervalMs);
    timer.unref();
    app.addHook("onClose", () => {
      clearInterval(timer);
      return Promise.resolve();
    });
  }
}
