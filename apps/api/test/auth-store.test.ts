/**
 * One contract, two implementations: every behaviour the routes rely on is
 * checked against MemoryAuthStore and against the Prisma store on a real
 * (PGlite) Postgres with the committed migrations. If they ever disagree,
 * tests that pass in memory could hide a production bug.
 */
import { createPrismaClient, type PrismaClient } from "@header-auditor/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createPrismaAuthStore, isUniqueViolation } from "../src/auth/prisma-store.js";
import {
  type AuthStore,
  EmailTakenError,
  isSessionExpired,
  MemoryAuthStore,
} from "../src/auth/store.js";
import { generateSessionToken, hashSessionToken } from "../src/auth/tokens.js";
import { startTestDatabase, type TestDatabase } from "./helpers/database.js";

let testDb: TestDatabase;
let prisma: PrismaClient;

beforeAll(async () => {
  testDb = await startTestDatabase();
  expect(new URL(testDb.url).hostname).toBe("127.0.0.1");
  prisma = createPrismaClient({ databaseUrl: testDb.url, maxConnections: 2 });
});

afterAll(async () => {
  await prisma.$disconnect();
  await testDb.stop();
});

let counter = 0;
function email(): string {
  counter += 1;
  return `user${String(counter)}@example.test`;
}

const HOUR = 3_600_000;
const HASH = "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g";

describe.each([
  ["MemoryAuthStore", (): AuthStore => new MemoryAuthStore()],
  ["Prisma store (PGlite)", (): AuthStore => createPrismaAuthStore(prisma)],
])("%s", (_name, makeStore) => {
  let store: AuthStore;
  beforeAll(() => {
    store = makeStore();
  });

  async function newSession(userId: string, createdAt = new Date(), ttlMs = 24 * HOUR) {
    return store.createSession({
      userId,
      tokenHash: hashSessionToken(generateSessionToken()),
      createdAt,
      expiresAt: new Date(createdAt.getTime() + ttlMs),
      userAgent: "vitest",
    });
  }

  it("creates users with a lower-cased email and finds them case-insensitively", async () => {
    const address = email();
    const user = await store.createUser(address.toUpperCase(), HASH);
    expect(user).toMatchObject({ email: address, passwordHash: HASH });
    expect(user.createdAt).toBeInstanceOf(Date);
    expect(await store.findUserByEmail(address.toUpperCase())).toEqual(user);
    expect(await store.findUserById(user.id)).toEqual(user);
    expect(await store.findUserByEmail("nobody@example.test")).toBeNull();
    expect(await store.findUserById("00000000-0000-4000-8000-000000000000")).toBeNull();
  });

  it("throws EmailTakenError for a duplicate email, in any case", async () => {
    const address = email();
    await store.createUser(address, HASH);
    await expect(store.createUser(address.toUpperCase(), HASH)).rejects.toBeInstanceOf(
      EmailTakenError,
    );
  });

  it("only one of two concurrent registrations for an email wins", async () => {
    const address = email();
    const results = await Promise.allSettled([
      store.createUser(address, HASH),
      store.createUser(address, HASH),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((r) => r.status === "rejected");
    expect(rejected?.reason).toBeInstanceOf(EmailTakenError);
  });

  it("updates a password hash and ignores unknown users", async () => {
    const user = await store.createUser(email(), HASH);
    await store.updatePasswordHash(user.id, "$argon2id$new");
    expect((await store.findUserById(user.id))?.passwordHash).toBe("$argon2id$new");
    await expect(
      store.updatePasswordHash("00000000-0000-4000-8000-000000000000", HASH),
    ).resolves.toBeUndefined();
  });

  it("creates, finds, touches and deletes sessions", async () => {
    const user = await store.createUser(email(), HASH);
    const createdAt = new Date("2026-11-22T10:00:00.000Z");
    const session = await newSession(user.id, createdAt);
    expect(session).toMatchObject({ userId: user.id, userAgent: "vitest", createdAt });
    expect(session.lastSeenAt).toEqual(createdAt);
    expect(await store.findSessionByTokenHash(session.tokenHash)).toEqual(session);

    const later = new Date(createdAt.getTime() + 5 * 60_000);
    await store.touchSession(session.id, later);
    expect((await store.findSessionByTokenHash(session.tokenHash))?.lastSeenAt).toEqual(later);

    await store.deleteSession(session.id);
    expect(await store.findSessionByTokenHash(session.tokenHash)).toBeNull();
    // Deleting or touching a session that is already gone is not an error.
    await expect(store.deleteSession(session.id)).resolves.toBeUndefined();
    await expect(store.touchSession(session.id, later)).resolves.toBeUndefined();
  });

  it("deletes every session of one user only", async () => {
    const alice = await store.createUser(email(), HASH);
    const bob = await store.createUser(email(), HASH);
    await newSession(alice.id);
    await newSession(alice.id);
    const bobs = await newSession(bob.id);
    expect(await store.deleteUserSessions(alice.id)).toBe(2);
    expect(await store.findSessionByTokenHash(bobs.tokenHash)).not.toBeNull();
  });

  it("prunes sessions past their absolute or idle deadline", async () => {
    const user = await store.createUser(email(), HASH);
    const now = new Date("2026-11-23T00:00:00.000Z");
    const idleMs = 2 * HOUR;
    const fresh = await newSession(user.id, new Date(now.getTime() - HOUR));
    const idle = await newSession(user.id, new Date(now.getTime() - 3 * HOUR));
    const absolute = await newSession(user.id, new Date(now.getTime() - 25 * HOUR), 24 * HOUR);
    await store.touchSession(absolute.id, new Date(now.getTime() - 60_000));

    expect(isSessionExpired(fresh, now, idleMs)).toBe(false);
    const removed = await store.deleteExpiredSessions(now, idleMs);
    expect(removed).toBeGreaterThanOrEqual(2);
    expect(await store.findSessionByTokenHash(fresh.tokenHash)).not.toBeNull();
    expect(await store.findSessionByTokenHash(idle.tokenHash)).toBeNull();
    expect(await store.findSessionByTokenHash(absolute.tokenHash)).toBeNull();
  });
});

describe("Prisma store specifics", () => {
  it("stores only the token hash, and the database rejects a raw token", async () => {
    const store = createPrismaAuthStore(prisma);
    const user = await store.createUser(email(), HASH);
    const token = generateSessionToken();
    const now = new Date();
    await expect(
      store.createSession({
        userId: user.id,
        tokenHash: token,
        createdAt: now,
        expiresAt: new Date(now.getTime() + HOUR),
        userAgent: null,
      }),
    ).rejects.toThrow();
  });

  it("deleting a user cascades to their sessions", async () => {
    const store = createPrismaAuthStore(prisma);
    const user = await store.createUser(email(), HASH);
    const now = new Date();
    const session = await store.createSession({
      userId: user.id,
      tokenHash: hashSessionToken(generateSessionToken()),
      createdAt: now,
      expiresAt: new Date(now.getTime() + HOUR),
      userAgent: null,
    });
    await prisma.user.delete({ where: { id: user.id } });
    expect(await store.findSessionByTokenHash(session.tokenHash)).toBeNull();
  });

  it("isUniqueViolation recognises Prisma's P2002 only", () => {
    expect(isUniqueViolation({ code: "P2002" })).toBe(true);
    expect(isUniqueViolation({ code: "P2025" })).toBe(false);
    expect(isUniqueViolation(new Error("P2002"))).toBe(false);
    expect(isUniqueViolation(null)).toBe(false);
  });
});
