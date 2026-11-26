/**
 * /sites over HTTP. The authorization suite runs twice: against the in-memory
 * stores and against Postgres (PGlite) through the Prisma stores, so the
 * "users can't touch each other's sites" guarantee is proven end to end
 * through real SQL, not only against a test double.
 */
import { createPrismaClient, type PrismaClient } from "@header-auditor/db";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { buildApp } from "../src/app.js";
import { createPrismaAuthStore } from "../src/auth/prisma-store.js";
import { MemoryAuthStore } from "../src/auth/store.js";
import type { Env } from "../src/config.js";
import { createPrismaSiteStore } from "../src/sites/prisma-store.js";
import { MemorySiteStore, type SiteStore } from "../src/sites/store.js";
import { fastHasher, ORIGIN, register, type Session, sessionFrom } from "./helpers/auth.js";
import { createTestApp, testConfig } from "./helpers/app.js";
import { startTestDatabase, type TestDatabase } from "./helpers/database.js";

let testDb: TestDatabase;
let prisma: PrismaClient;

beforeAll(async () => {
  testDb = await startTestDatabase();
  expect(new URL(testDb.url).hostname).toBe("127.0.0.1");
  prisma = createPrismaClient({ databaseUrl: testDb.url, maxConnections: 4 });
});

afterAll(async () => {
  await prisma.$disconnect();
  await testDb.stop();
});

const ENV: Env = { AUTH_COOKIE_SECURE: "false" };
let userCounter = 0;

interface Backend {
  readonly name: string;
  make(env?: Env): Promise<{ app: FastifyInstance; sites: SiteStore }>;
}

async function memoryApp(env: Env = {}): Promise<{ app: FastifyInstance; sites: SiteStore }> {
  const sites = new MemorySiteStore();
  const { app } = await createTestApp({
    env: { ...ENV, ...env },
    auth: { store: new MemoryAuthStore(), hasher: fastHasher(), pruneIntervalMs: 0 },
    sites: { store: sites },
  });
  return { app, sites };
}

const BACKENDS: readonly Backend[] = [
  { name: "memory stores", make: memoryApp },
  {
    name: "Prisma stores (PGlite)",
    async make(env: Env = {}) {
      const sites = createPrismaSiteStore(prisma);
      const { app } = await createTestApp({
        env: { ...ENV, ...env },
        auth: { store: createPrismaAuthStore(prisma), hasher: fastHasher(), pruneIntervalMs: 0 },
        sites: { store: sites },
      });
      return { app, sites };
    },
  },
];

async function signUp(app: FastifyInstance): Promise<Session> {
  userCounter += 1;
  const response = await register(app, `sites${String(userCounter)}@example.test`);
  expect(response.statusCode).toBe(201);
  return sessionFrom(response);
}

type Method = "GET" | "POST" | "PATCH" | "DELETE";

function call(
  app: FastifyInstance,
  session: Session | null,
  method: Method,
  url: string,
  payload?: unknown,
  headers: Record<string, string> = {},
): Promise<LightMyRequestResponse> {
  return app.inject({
    method,
    url,
    headers: {
      origin: ORIGIN,
      ...(session === null ? {} : { cookie: session.cookie, "x-csrf-token": session.csrfToken }),
      ...headers,
    },
    ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
  });
}

async function addSite(
  app: FastifyInstance,
  session: Session,
  body: Record<string, unknown>,
): Promise<Record<string, unknown> & { id: string }> {
  const response = await call(app, session, "POST", "/sites", body);
  expect(response.statusCode, response.body).toBe(201);
  return response.json();
}

function errorOf(response: LightMyRequestResponse): { code: string; message: string } {
  const { code, message } = response.json<{ error: { code: string; message: string } }>().error;
  return { code, message };
}

describe.each(BACKENDS)("sites authorization ($name)", (backend) => {
  let app: FastifyInstance;
  let alice: Session;
  let bob: Session;
  let alicesSite: { id: string };

  beforeAll(async () => {
    ({ app } = await backend.make());
    alice = await signUp(app);
    bob = await signUp(app);
    alicesSite = await addSite(app, alice, {
      name: "Alice's shop",
      url: "https://alice.example.com",
    });
  });

  afterAll(async () => {
    await app.close();
  });

  it("lets the owner read, update and list their site", async () => {
    const read = await call(app, alice, "GET", `/sites/${alicesSite.id}`);
    expect(read.statusCode).toBe(200);
    expect(read.json()).toMatchObject({ id: alicesSite.id, url: "https://alice.example.com" });

    const list = await call(app, alice, "GET", "/sites");
    expect(list.json<{ items: { id: string }[] }>().items.map((s) => s.id)).toContain(
      alicesSite.id,
    );

    const patched = await call(app, alice, "PATCH", `/sites/${alicesSite.id}`, {
      name: "Alice's store",
    });
    expect(patched.statusCode).toBe(200);
    expect(patched.json()).toMatchObject({ name: "Alice's store" });
  });

  it("never shows Alice's site in Bob's list", async () => {
    const list = await call(app, bob, "GET", "/sites");
    expect(list.statusCode).toBe(200);
    expect(list.json()).toEqual({ items: [], nextCursor: null });
  });

  it.each([
    ["GET", undefined],
    ["PATCH", { name: "pwned" }],
    ["DELETE", undefined],
  ] as const)("answers Bob's %s on Alice's site with a plain 404", async (method, body) => {
    const response = await call(app, bob, method, `/sites/${alicesSite.id}`, body);
    expect(response.statusCode).toBe(404);
    expect(errorOf(response)).toEqual({ code: "SITE_NOT_FOUND", message: "Site not found" });
  });

  it("gives an identical 404 for someone else's site and a site that doesn't exist", async () => {
    const theirs = await call(app, bob, "GET", `/sites/${alicesSite.id}`);
    const missing = await call(app, bob, "GET", "/sites/00000000-0000-4000-8000-000000000000");
    const strip = (r: LightMyRequestResponse) => ({
      status: r.statusCode,
      error: errorOf(r),
      keys: Object.keys(r.json<{ error: object }>().error).sort(),
    });
    expect(strip(theirs)).toEqual(strip(missing));
  });

  it("leaves Alice's site intact after Bob's attempts", async () => {
    await call(app, bob, "PATCH", `/sites/${alicesSite.id}`, { name: "pwned" });
    await call(app, bob, "DELETE", `/sites/${alicesSite.id}`);
    const read = await call(app, alice, "GET", `/sites/${alicesSite.id}`);
    expect(read.statusCode).toBe(200);
    expect(read.json()).toMatchObject({ name: "Alice's store" });
  });

  it("lets two users add the same URL independently", async () => {
    const bobs = await addSite(app, bob, { name: "Same", url: "alice.example.com" });
    expect(bobs.id).not.toBe(alicesSite.id);
    expect(bobs.verificationToken).not.toBe(
      (await call(app, alice, "GET", `/sites/${alicesSite.id}`)).json<{
        verificationToken: string;
      }>().verificationToken,
    );
  });

  it("does not let Bob page into Alice's list with her cursor", async () => {
    for (const n of [1, 2]) {
      await addSite(app, alice, {
        name: `A${String(n)}`,
        url: `https://a${String(n)}.example.com`,
      });
    }
    const page = await call(app, alice, "GET", "/sites?limit=1");
    const { nextCursor } = page.json<{ nextCursor: string | null }>();
    expect(nextCursor).not.toBeNull();
    const bobs = await call(app, bob, "GET", `/sites?cursor=${nextCursor ?? ""}`);
    expect(bobs.statusCode).toBe(200);
    const ids = bobs.json<{ items: { id: string }[] }>().items.map((s) => s.id);
    expect(ids).not.toContain(alicesSite.id);
    const aliceIds = new Set(
      (await call(app, alice, "GET", "/sites?limit=100"))
        .json<{ items: { id: string }[] }>()
        .items.map((s) => s.id),
    );
    expect(ids.some((id) => aliceIds.has(id))).toBe(false);
  });

  it("forgets a deleted site", async () => {
    const temp = await addSite(app, alice, { name: "Temp", url: "https://temp.example.com" });
    const deleted = await call(app, alice, "DELETE", `/sites/${temp.id}`);
    expect(deleted.statusCode).toBe(204);
    expect(deleted.body).toBe("");
    expect((await call(app, alice, "GET", `/sites/${temp.id}`)).statusCode).toBe(404);
    expect((await call(app, alice, "DELETE", `/sites/${temp.id}`)).statusCode).toBe(404);
  });
});

describe("sites routes", () => {
  let app: FastifyInstance;
  let sites: SiteStore;
  let me: Session;

  beforeAll(async () => {
    ({ app, sites } = await memoryApp({ SITES_MAX_PER_USER: "100" }));
    me = await signUp(app);
  });

  afterAll(async () => {
    await app.close();
  });

  describe("authentication and CSRF", () => {
    it.each([
      ["GET", "/sites"],
      ["POST", "/sites"],
      ["GET", "/sites/00000000-0000-4000-8000-000000000000"],
      ["PATCH", "/sites/00000000-0000-4000-8000-000000000000"],
      ["DELETE", "/sites/00000000-0000-4000-8000-000000000000"],
    ] as const)("%s %s requires a session", async (method, url) => {
      const response = await call(
        app,
        null,
        method,
        url,
        method === "POST" || method === "PATCH" ? { name: "x" } : undefined,
      );
      expect(response.statusCode).toBe(401);
      expect(errorOf(response).code).toBe("AUTH_REQUIRED");
    });

    it.each(["POST", "PATCH", "DELETE"] as const)(
      "%s without the CSRF token is refused",
      async (method) => {
        const site = await addSite(app, me, {
          name: "CSRF",
          url: `https://csrf-${method.toLowerCase()}.example.com`,
        });
        const url = method === "POST" ? "/sites" : `/sites/${site.id}`;
        const response = await app.inject({
          method,
          url,
          headers: { origin: ORIGIN, cookie: me.cookie },
          ...(method === "DELETE" ? {} : { payload: { name: "x", url: "https://x.example.com" } }),
        });
        expect(response.statusCode).toBe(403);
        expect(errorOf(response).code).toBe("CSRF_TOKEN_INVALID");
      },
    );

    it("refuses a cross-site origin before anything else", async () => {
      const response = await call(
        app,
        me,
        "POST",
        "/sites",
        { name: "x", url: "https://x.example.com" },
        { origin: "https://evil.example" },
      );
      expect(response.statusCode).toBe(403);
      expect(errorOf(response).code).toBe("CSRF_ORIGIN_REJECTED");
    });

    it("refuses form-encoded bodies", async () => {
      const response = await call(app, me, "POST", "/sites", undefined, {
        "content-type": "application/x-www-form-urlencoded",
      });
      expect(response.statusCode).toBe(415);
    });
  });

  describe("POST /sites", () => {
    it("creates a site with normalised fields and a Location header", async () => {
      const response = await call(app, me, "POST", "/sites", {
        name: "  My blog  ",
        url: "Blog.Example.COM",
        firstPartyHosts: ["CDN.example.com", "cdn.example.com.", "static.example.com"],
      });
      expect(response.statusCode).toBe(201);
      const body = response.json<Record<string, unknown> & { id: string }>();
      expect(response.headers.location).toBe(`/sites/${body.id}`);
      expect(body).toEqual({
        id: expect.stringMatching(/^[0-9a-f-]{36}$/) as unknown,
        name: "My blog",
        url: "https://blog.example.com",
        schedule: "none",
        nextScanAt: null,
        firstPartyHosts: ["cdn.example.com", "static.example.com"],
        verified: false,
        verifiedAt: null,
        verificationToken: expect.stringMatching(/^[0-9a-f]{64}$/) as unknown,
        verificationRecord: {
          name: "_header-auditor-challenge.blog.example.com",
          type: "TXT",
          value: expect.stringMatching(/^header-auditor-verification=[0-9a-f]{64}$/) as unknown,
        },
        createdAt: expect.any(String) as unknown,
        updatedAt: expect.any(String) as unknown,
      });
      // ownerId is internal; the client already knows who it is.
      expect(body).not.toHaveProperty("ownerId");
    });

    it("refuses the same origin twice, however it is spelled", async () => {
      await addSite(app, me, { name: "Dup", url: "https://dup.example.com" });
      const response = await call(app, me, "POST", "/sites", {
        name: "Dup again",
        url: "HTTPS://DUP.example.com:443/",
      });
      expect(response.statusCode).toBe(409);
      expect(errorOf(response).code).toBe("SITE_EXISTS");
    });

    it.each([
      [{ url: "https://x.example.com" }, "name"],
      [{ name: "", url: "https://x.example.com" }, "name"],
      [{ name: "a".repeat(101), url: "https://x.example.com" }, "name"],
      [{ name: "bad\u0007name", url: "https://x.example.com" }, "name"],
      [{ name: "x" }, "url"],
      [{ name: "x", url: 42 }, "url"],
      [{ name: "x", url: "https://x.example.com/admin" }, "url"],
      [{ name: "x", url: "http://169.254.169.254" }, "url"],
      [{ name: "x", url: "http://localhost:8080" }, "url"],
      [{ name: "x", url: "file:///etc/passwd" }, "url"],
      [{ name: "x", url: "https://x.example.com", schedule: "hourly" }, "schedule"],
      [
        { name: "x", url: "https://x.example.com", firstPartyHosts: ["https://cdn.x.com"] },
        "firstPartyHosts.0",
      ],
      [
        { name: "x", url: "https://x.example.com", firstPartyHosts: "cdn.x.com" },
        "firstPartyHosts",
      ],
      [
        {
          name: "x",
          url: "https://x.example.com",
          firstPartyHosts: Array.from({ length: 21 }, (_, i) => `h${String(i)}.example.com`),
        },
        "firstPartyHosts",
      ],
      [
        {
          name: "x",
          url: "https://x.example.com",
          ownerId: "00000000-0000-4000-8000-000000000000",
        },
        "<root>",
      ],
      [{ name: "x", url: "https://x.example.com", verifiedAt: "2026-01-01T00:00:00Z" }, "<root>"],
      [{ name: "x", url: "https://x.example.com", verificationToken: "a".repeat(64) }, "<root>"],
    ])("rejects %j with a validation error on %s", async (body, path) => {
      const response = await call(app, me, "POST", "/sites", body);
      expect(response.statusCode).toBe(400);
      const error = response.json<{ error: { code: string; details: { path: string }[] } }>().error;
      expect(error.code).toBe("VALIDATION_FAILED");
      expect(error.details.map((d) => d.path)).toContain(path);
    });

    it("refuses to start an unverified site on a schedule", async () => {
      const response = await call(app, me, "POST", "/sites", {
        name: "Sched",
        url: "https://sched.example.com",
        schedule: "daily",
      });
      expect(response.statusCode).toBe(409);
      expect(errorOf(response).code).toBe("SITE_NOT_VERIFIED");
    });

    it("enforces the per-user site limit", async () => {
      const { app: small } = await memoryApp({ SITES_MAX_PER_USER: "2" });
      const user = await signUp(small);
      await addSite(small, user, { name: "1", url: "https://one.example.com" });
      await addSite(small, user, { name: "2", url: "https://two.example.com" });
      const response = await call(small, user, "POST", "/sites", {
        name: "3",
        url: "https://three.example.com",
      });
      expect(response.statusCode).toBe(409);
      expect(errorOf(response)).toEqual({
        code: "SITE_LIMIT_REACHED",
        message: "You can add at most 2 sites",
      });
      await small.close();
    });

    it("accepts localhost targets only when SITES_ALLOW_PRIVATE_TARGETS is on", async () => {
      const { app: dev } = await memoryApp({ SITES_ALLOW_PRIVATE_TARGETS: "true" });
      const user = await signUp(dev);
      const site = await addSite(dev, user, { name: "mock", url: "http://127.0.0.1:4010" });
      expect(site.url).toBe("http://127.0.0.1:4010");
      await dev.close();
    });
  });

  describe("GET /sites", () => {
    it("paginates newest first", async () => {
      const { app: fresh } = await memoryApp();
      const user = await signUp(fresh);
      const names = ["s1", "s2", "s3", "s4", "s5"];
      for (const name of names) {
        await addSite(fresh, user, { name, url: `https://${name}.example.com` });
        await new Promise((resolve) => setTimeout(resolve, 2));
      }
      const seen: string[] = [];
      let cursor: string | null = null;
      let pages = 0;
      do {
        const query: string = cursor === null ? "?limit=2" : `?limit=2&cursor=${cursor}`;
        const response = await call(fresh, user, "GET", `/sites${query}`);
        expect(response.statusCode).toBe(200);
        const body = response.json<{ items: { name: string }[]; nextCursor: string | null }>();
        seen.push(...body.items.map((s) => s.name));
        cursor = body.nextCursor;
        pages += 1;
      } while (cursor !== null);
      expect(seen).toEqual([...names].reverse());
      expect(pages).toBe(3);
      await fresh.close();
    });

    it("returns nextCursor null when the page is exactly full", async () => {
      const { app: fresh } = await memoryApp();
      const user = await signUp(fresh);
      await addSite(fresh, user, { name: "only", url: "https://only.example.com" });
      const body = (await call(fresh, user, "GET", "/sites?limit=1")).json<{
        nextCursor: string | null;
      }>();
      expect(body.nextCursor).toBeNull();
      await fresh.close();
    });

    it.each([
      ["limit=0", "limit"],
      ["limit=101", "limit"],
      ["limit=abc", "limit"],
      ["limit=1.5", "limit"],
      ["cursor=not-a-cursor!", "cursor"],
      ["cursor=MTIz", "cursor"],
      ["sort=name", "<root>"],
    ])("rejects ?%s", async (query, path) => {
      const response = await call(app, me, "GET", `/sites?${query}`);
      expect(response.statusCode).toBe(400);
      const error = response.json<{ error: { details: { path: string }[] } }>().error;
      expect(error.details.map((d) => d.path)).toContain(path);
    });
  });

  describe("GET/PATCH/DELETE /sites/:id", () => {
    it.each(["not-a-uuid", "1", "' OR 1=1 --", "00000000-0000-4000-8000-00000000000g"])(
      "answers a malformed id %j with 404",
      async (id) => {
        const response = await call(app, me, "GET", `/sites/${encodeURIComponent(id)}`);
        expect(response.statusCode).toBe(404);
        expect(errorOf(response).code).toBe("SITE_NOT_FOUND");
      },
    );

    it("accepts an upper-case id", async () => {
      const site = await addSite(app, me, { name: "Upper", url: "https://upper.example.com" });
      const response = await call(app, me, "GET", `/sites/${site.id.toUpperCase()}`);
      expect(response.statusCode).toBe(200);
    });

    it("patches name and first-party hosts", async () => {
      const site = await addSite(app, me, { name: "Patch", url: "https://patch.example.com" });
      const response = await call(app, me, "PATCH", `/sites/${site.id}`, {
        name: "Patched",
        firstPartyHosts: ["Assets.Example.com"],
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({
        name: "Patched",
        url: "https://patch.example.com",
        firstPartyHosts: ["assets.example.com"],
      });
    });

    it.each([
      [{}, "<root>"],
      [{ url: "https://other.example.com" }, "<root>"],
      [{ name: "" }, "name"],
      [{ schedule: "monthly" }, "schedule"],
      [{ verifiedAt: "2026-01-01T00:00:00Z" }, "<root>"],
    ])("rejects patch %j", async (body, path) => {
      const site = await addSite(app, me, {
        name: "Bad patch",
        url: `https://bp${String(Math.random()).slice(2, 10)}.example.com`,
      });
      const response = await call(app, me, "PATCH", `/sites/${site.id}`, body);
      expect(response.statusCode).toBe(400);
      const error = response.json<{ error: { details: { path: string }[] } }>().error;
      expect(error.details.map((d) => d.path)).toContain(path);
    });

    it("only allows a schedule once the site is verified", async () => {
      const site = await addSite(app, me, { name: "Verify", url: "https://verify.example.com" });
      const refused = await call(app, me, "PATCH", `/sites/${site.id}`, { schedule: "weekly" });
      expect(refused.statusCode).toBe(409);
      expect(errorOf(refused).code).toBe("SITE_NOT_VERIFIED");

      // Turning scheduling off is always allowed.
      const off = await call(app, me, "PATCH", `/sites/${site.id}`, { schedule: "none" });
      expect(off.statusCode).toBe(200);

      (sites as MemorySiteStore).markVerified(site.id, new Date("2026-11-23T12:00:00.000Z"));
      const allowed = await call(app, me, "PATCH", `/sites/${site.id}`, { schedule: "weekly" });
      expect(allowed.statusCode).toBe(200);
      expect(allowed.json()).toMatchObject({
        schedule: "weekly",
        nextScanAt: expect.any(String) as unknown,
        verified: true,
        verifiedAt: "2026-11-23T12:00:00.000Z",
      });
    });
  });
});

describe("buildApp wiring", () => {
  it("refuses sites without auth", async () => {
    await expect(
      buildApp({ config: testConfig(), sites: { store: new MemorySiteStore() } }),
    ).rejects.toThrow(/requires `auth`/);
  });

  it("does not register /sites when no site store is given", async () => {
    const { app } = await createTestApp({
      env: ENV,
      auth: { store: new MemoryAuthStore(), hasher: fastHasher(), pruneIntervalMs: 0 },
    });
    const response = await app.inject({ method: "GET", url: "/sites" });
    expect(response.statusCode).toBe(404);
    expect(errorOf(response).code).toBe("NOT_FOUND");
    await app.close();
  });
});
