import type { FastifyInstance, LightMyRequestResponse } from "fastify";

import { createPasswordHasher, type PasswordHasher } from "../../src/auth/password.js";

/** Minimum argon2id cost: same code path as production, milliseconds per hash. */
export const FAST_ARGON2 = { memoryCost: 64, timeCost: 1, parallelism: 1 } as const;

export function fastHasher(): PasswordHasher {
  return createPasswordHasher(FAST_ARGON2);
}

export const ORIGIN = "http://localhost:3000";
export const PASSWORD = "correct horse battery staple";

/** Mutable clock for idle/absolute-expiry tests. */
export class TestClock {
  constructor(private ms = Date.parse("2026-11-22T12:00:00.000Z")) {}

  now = (): Date => new Date(this.ms);

  advance(ms: number): void {
    this.ms += ms;
  }
}

export interface Session {
  /** "name=value" for the Cookie header. */
  readonly cookie: string;
  readonly csrfToken: string;
  readonly body: Record<string, unknown>;
}

export function setCookieHeaders(response: LightMyRequestResponse): string[] {
  const header = response.headers["set-cookie"];
  if (header === undefined) return [];
  return Array.isArray(header) ? header : [header];
}

export function sessionFrom(response: LightMyRequestResponse): Session {
  const [first] = setCookieHeaders(response);
  if (first === undefined)
    throw new Error(`no Set-Cookie in ${String(response.statusCode)} response`);
  const cookie = first.split(";")[0] ?? "";
  const body = response.json<Record<string, unknown>>();
  if (typeof body.csrfToken !== "string") throw new Error("response has no csrfToken");
  return { cookie, csrfToken: body.csrfToken, body };
}

export function register(
  app: FastifyInstance,
  email: string,
  password = PASSWORD,
  headers: Record<string, string> = {},
): Promise<LightMyRequestResponse> {
  return app.inject({
    method: "POST",
    url: "/auth/register",
    headers: { origin: ORIGIN, ...headers },
    payload: { email, password },
  });
}

export function login(
  app: FastifyInstance,
  email: string,
  password = PASSWORD,
  headers: Record<string, string> = {},
): Promise<LightMyRequestResponse> {
  return app.inject({
    method: "POST",
    url: "/auth/login",
    headers: { origin: ORIGIN, ...headers },
    payload: { email, password },
  });
}
