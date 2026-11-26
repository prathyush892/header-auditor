/**
 * The SiteStore contract, run against MemorySiteStore and against the Prisma
 * store on a real (PGlite) Postgres with the committed migrations. Owner
 * scoping is asserted at this layer too, not only through HTTP: the store is
 * the last place a missing `ownerId` filter could hide.
 */
import { createPrismaClient, type PrismaClient } from "@header-auditor/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createPrismaSiteStore, isRecordNotFound } from "../src/sites/prisma-store.js";
import { generateVerificationToken } from "../src/sites/routes.js";
import {
  MemorySiteStore,
  type NewSite,
  SiteExistsError,
  SiteLimitError,
  type SiteRecord,
  type SiteStore,
} from "../src/sites/store.js";
import { TestClock } from "./helpers/auth.js";
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

const HASH = "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g";
const MISSING_ID = "00000000-0000-4000-8000-000000000000";
let counter = 0;

/** Sites reference users by foreign key, so the Prisma variant needs real user rows. */
async function newOwner(usesDatabase: boolean): Promise<string> {
  counter += 1;
  if (!usesDatabase) return crypto.randomUUID();
  const user = await prisma.user.create({
    data: { email: `owner${String(counter)}@example.test`, passwordHash: HASH },
  });
  return user.id;
}

function site(ownerId: string, n: number, overrides: Partial<NewSite> = {}): NewSite {
  return {
    ownerId,
    name: `Site ${String(n)}`,
    url: `https://site${String(n)}.example.com`,
    verificationToken: generateVerificationToken(),
    schedule: "NONE",
    firstPartyHosts: [],
    ...overrides,
  };
}

describe.each([
  ["MemorySiteStore", false, (): SiteStore => new MemorySiteStore()],
  ["Prisma store (PGlite)", true, (): SiteStore => createPrismaSiteStore(prisma)],
])("%s", (_name, usesDatabase, makeStore) => {
  let store: SiteStore;
  beforeAll(() => {
    store = makeStore();
  });

  const owner = (): Promise<string> => newOwner(usesDatabase);

  it("creates a site and finds it for its owner", async () => {
    const ownerId = await owner();
    const input = site(ownerId, 1, { firstPartyHosts: ["cdn.example.com"] });
    const created = await store.createSite(input, 10);
    expect(created).toMatchObject({
      ownerId,
      name: "Site 1",
      url: "https://site1.example.com",
      verificationToken: input.verificationToken,
      verifiedAt: null,
      schedule: "NONE",
      firstPartyHosts: ["cdn.example.com"],
    });
    expect(created.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(created.createdAt).toBeInstanceOf(Date);
    expect(await store.findSite(ownerId, created.id)).toEqual(created);
  });

  it("never returns another owner's site", async () => {
    const alice = await owner();
    const bob = await owner();
    const alices = await store.createSite(site(alice, 2), 10);

    expect(await store.findSite(bob, alices.id)).toBeNull();
    expect(await store.listSites(bob, { limit: 10 })).toEqual([]);
    expect(await store.updateSite(bob, alices.id, { name: "pwned" })).toBeNull();
    expect(await store.deleteSite(bob, alices.id)).toBe(false);

    // Alice's site is untouched by Bob's attempts.
    expect(await store.findSite(alice, alices.id)).toMatchObject({ name: "Site 2" });
  });

  it("returns null/false for ids that don't exist", async () => {
    const ownerId = await owner();
    expect(await store.findSite(ownerId, MISSING_ID)).toBeNull();
    expect(await store.updateSite(ownerId, MISSING_ID, { name: "x" })).toBeNull();
    expect(await store.deleteSite(ownerId, MISSING_ID)).toBe(false);
  });

  it("rejects a duplicate URL for the same owner but allows it for another", async () => {
    const alice = await owner();
    const bob = await owner();
    await store.createSite(site(alice, 3), 10);
    await expect(store.createSite(site(alice, 3), 10)).rejects.toBeInstanceOf(SiteExistsError);
    await expect(store.createSite(site(bob, 3), 10)).resolves.toMatchObject({ ownerId: bob });
  });

  it("enforces the per-owner quota", async () => {
    const ownerId = await owner();
    await store.createSite(site(ownerId, 10), 2);
    await store.createSite(site(ownerId, 11), 2);
    const error: unknown = await store.createSite(site(ownerId, 12), 2).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SiteLimitError);
    expect((error as SiteLimitError).limit).toBe(2);
    // Another owner has their own quota.
    await expect(store.createSite(site(await owner(), 12), 2)).resolves.toBeDefined();
  });

  it("holds the quota under concurrent creates", async () => {
    const ownerId = await owner();
    const results = await Promise.allSettled(
      Array.from({ length: 6 }, (_, i) => store.createSite(site(ownerId, 100 + i), 3)),
    );
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(3);
    const rejected = results.filter((r) => r.status === "rejected");
    expect(rejected.every((r) => r.reason instanceof SiteLimitError)).toBe(true);
    expect(await store.listSites(ownerId, { limit: 10 })).toHaveLength(3);
  });

  it("lets only one of two concurrent creates for the same URL win", async () => {
    const ownerId = await owner();
    const results = await Promise.allSettled([
      store.createSite(site(ownerId, 200), 10),
      store.createSite(site(ownerId, 200), 10),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const [failure] = results.filter((r) => r.status === "rejected");
    expect(failure?.reason).toBeInstanceOf(SiteExistsError);
  });

  it("updates only the given fields and bumps updatedAt", async () => {
    const ownerId = await owner();
    const created = await store.createSite(site(ownerId, 20), 10);
    await new Promise((resolve) => setTimeout(resolve, 5));
    const renamed = await store.updateSite(ownerId, created.id, { name: "Renamed" });
    expect(renamed).toMatchObject({ name: "Renamed", url: created.url, schedule: "NONE" });
    expect(renamed?.updatedAt.getTime()).toBeGreaterThan(created.updatedAt.getTime());

    const hosts = await store.updateSite(ownerId, created.id, {
      schedule: "WEEKLY",
      firstPartyHosts: ["a.example.com", "b.example.com"],
    });
    expect(hosts).toMatchObject({
      name: "Renamed",
      schedule: "WEEKLY",
      firstPartyHosts: ["a.example.com", "b.example.com"],
    });
    expect(await store.findSite(ownerId, created.id)).toEqual(hosts);
  });

  it("deletes a site once", async () => {
    const ownerId = await owner();
    const created = await store.createSite(site(ownerId, 30), 10);
    expect(await store.deleteSite(ownerId, created.id)).toBe(true);
    expect(await store.deleteSite(ownerId, created.id)).toBe(false);
    expect(await store.findSite(ownerId, created.id)).toBeNull();
    // The freed slot and URL can be reused.
    await expect(store.createSite(site(ownerId, 30), 1)).resolves.toBeDefined();
  });

  it("pages newest first with a keyset cursor, without gaps or overlaps", async () => {
    const ownerId = await owner();
    const created: SiteRecord[] = [];
    for (let i = 0; i < 7; i += 1) created.push(await store.createSite(site(ownerId, 40 + i), 20));
    const expected = [...created]
      .sort((a, b) =>
        b.createdAt.getTime() !== a.createdAt.getTime()
          ? b.createdAt.getTime() - a.createdAt.getTime()
          : b.id < a.id
            ? -1
            : 1,
      )
      .map((s) => s.id);

    const seen: string[] = [];
    let after: SiteRecord | undefined;
    for (;;) {
      const page = await store.listSites(ownerId, {
        limit: 3,
        ...(after === undefined ? {} : { after }),
      });
      seen.push(...page.map((s) => s.id));
      if (page.length < 3) break;
      after = page.at(-1);
    }
    expect(seen).toEqual(expected);
  });

  it("orders ties on createdAt by id", async () => {
    const ownerId = await owner();
    const a = await store.createSite(site(ownerId, 60), 10);
    const b = await store.createSite(site(ownerId, 61), 10);
    if (usesDatabase) {
      // Force identical timestamps so only the id tiebreak decides.
      await prisma.site.updateMany({
        where: { ownerId },
        data: { createdAt: new Date("2026-01-01T00:00:00.000Z") },
      });
    } else {
      return; // MemorySiteStore tie-breaking is covered by compareNewestFirst's unit test.
    }
    const ids = (await store.listSites(ownerId, { limit: 10 })).map((s) => s.id);
    expect(ids).toEqual([a.id, b.id].sort().reverse());
    const first = await store.listSites(ownerId, { limit: 1 });
    const [head] = first;
    if (head === undefined) throw new Error("expected a site");
    const rest = await store.listSites(ownerId, { limit: 10, after: head });
    expect(rest.map((s) => s.id)).toEqual(ids.slice(1));
  });
});

describe("Prisma site store specifics", () => {
  it("relies on ON DELETE CASCADE when a user is deleted", async () => {
    const store = createPrismaSiteStore(prisma);
    const ownerId = await newOwner(true);
    const created = await store.createSite(site(ownerId, 70), 10);
    await prisma.user.delete({ where: { id: ownerId } });
    expect(await prisma.site.findUnique({ where: { id: created.id } })).toBeNull();
  });

  it("refuses a site for an owner that doesn't exist (foreign key)", async () => {
    const store = createPrismaSiteStore(prisma);
    await expect(store.createSite(site(MISSING_ID, 71), 10)).rejects.toThrow();
  });

  it("is checked by the database: non-http URLs are refused even if the API let one through", async () => {
    const store = createPrismaSiteStore(prisma);
    const ownerId = await newOwner(true);
    await expect(
      store.createSite(site(ownerId, 72, { url: "javascript:alert(1)" }), 10),
    ).rejects.toThrow();
  });

  it("recognises Prisma's record-not-found error", () => {
    expect(isRecordNotFound({ code: "P2025" })).toBe(true);
    expect(isRecordNotFound({ code: "P2002" })).toBe(false);
    expect(isRecordNotFound(null)).toBe(false);
    expect(isRecordNotFound(new Error("x"))).toBe(false);
  });
});

describe.each([
  ["MemorySiteStore", false, (clock: TestClock): SiteStore => new MemorySiteStore(clock.now)],
  [
    "Prisma store (PGlite)",
    true,
    (clock: TestClock): SiteStore => createPrismaSiteStore(prisma, clock.now),
  ],
])("%s: next_scan_at", (_name, usesDatabase, makeStore) => {
  const HOUR = 3_600_000;
  let clock: TestClock;
  let store: SiteStore;
  beforeAll(() => {
    clock = new TestClock();
    store = makeStore(clock);
  });

  const owner = (): Promise<string> => newOwner(usesDatabase);

  it("is null without a schedule and 'now' for a site created on one", async () => {
    const ownerId = await owner();
    const off = await store.createSite(site(ownerId, 200), 10);
    expect(off.nextScanAt).toBeNull();
    const on = await store.createSite(site(ownerId, 201, { schedule: "DAILY" }), 10);
    expect(on.nextScanAt).toEqual(clock.now());
  });

  it("is set when a schedule is enabled, kept when re-sent, reset on a switch, cleared on NONE", async () => {
    const ownerId = await owner();
    const created = await store.createSite(site(ownerId, 202), 10);

    const enabledAt = clock.now();
    const enabled = await store.updateSite(ownerId, created.id, { schedule: "DAILY" });
    expect(enabled?.nextScanAt).toEqual(enabledAt);

    clock.advance(HOUR);
    // A client re-saving the whole form must not make the site due again.
    const resent = await store.updateSite(ownerId, created.id, {
      schedule: "DAILY",
      name: "Renamed",
    });
    expect(resent).toMatchObject({ name: "Renamed", schedule: "DAILY", nextScanAt: enabledAt });

    clock.advance(HOUR);
    const switched = await store.updateSite(ownerId, created.id, { schedule: "WEEKLY" });
    expect(switched?.nextScanAt).toEqual(clock.now());

    const off = await store.updateSite(ownerId, created.id, { schedule: "NONE" });
    expect(off).toMatchObject({ schedule: "NONE", nextScanAt: null });
    expect(await store.findSite(ownerId, created.id)).toEqual(off);
  });

  it("bumps updatedAt on a schedule-only change", async () => {
    const ownerId = await owner();
    const created = await store.createSite(site(ownerId, 203), 10);
    // Prisma stamps @updatedAt with its own clock, so move both clocks forward.
    clock.advance(HOUR);
    await new Promise((resolve) => setTimeout(resolve, 5));
    const updated = await store.updateSite(ownerId, created.id, { schedule: "WEEKLY" });
    expect(updated?.updatedAt.getTime()).toBeGreaterThan(created.updatedAt.getTime());
  });

  it("can't change another owner's schedule", async () => {
    const alice = await owner();
    const bob = await owner();
    const created = await store.createSite(site(alice, 204), 10);
    expect(await store.updateSite(bob, created.id, { schedule: "DAILY" })).toBeNull();
    expect((await store.findSite(alice, created.id))?.nextScanAt).toBeNull();
  });
});

describe.each([
  ["MemorySiteStore", false, (): SiteStore => new MemorySiteStore()],
  ["Prisma store (PGlite)", true, (): SiteStore => createPrismaSiteStore(prisma)],
])("recordVerification on %s", (_name, usesDatabase, makeStore) => {
  let store: SiteStore;
  beforeAll(() => {
    store = makeStore();
  });

  const owner = (): Promise<string> => newOwner(usesDatabase);
  const FIRST = new Date("2026-11-26T10:00:00.000Z");
  const LATER = new Date("2026-11-27T10:00:00.000Z");

  it("marks the site verified and keeps the first verification time", async () => {
    const ownerId = await owner();
    const created = await store.createSite(site(ownerId, 300), 10);
    const verified = await store.recordVerification(
      ownerId,
      created.id,
      created.verificationToken,
      FIRST,
    );
    expect(verified).toMatchObject({ id: created.id, verifiedAt: FIRST });

    const again = await store.recordVerification(
      ownerId,
      created.id,
      created.verificationToken,
      LATER,
    );
    expect(again?.verifiedAt).toEqual(FIRST);
    expect((await store.findSite(ownerId, created.id))?.verifiedAt).toEqual(FIRST);
  });

  it("does nothing when the token is not the site's current one", async () => {
    const ownerId = await owner();
    const created = await store.createSite(site(ownerId, 301), 10);
    const result = await store.recordVerification(
      ownerId,
      created.id,
      generateVerificationToken(),
      FIRST,
    );
    expect(result).toMatchObject({ id: created.id, verifiedAt: null });
  });

  it("can't verify another owner's site, and misses return null", async () => {
    const alice = await owner();
    const bob = await owner();
    const created = await store.createSite(site(alice, 302), 10);
    expect(
      await store.recordVerification(bob, created.id, created.verificationToken, FIRST),
    ).toBeNull();
    expect(
      await store.recordVerification(alice, MISSING_ID, created.verificationToken, FIRST),
    ).toBeNull();
    expect((await store.findSite(alice, created.id))?.verifiedAt).toBeNull();
  });

  it("lets two concurrent verifications settle on one timestamp", async () => {
    const ownerId = await owner();
    const created = await store.createSite(site(ownerId, 303), 10);
    const [a, b] = await Promise.all([
      store.recordVerification(ownerId, created.id, created.verificationToken, FIRST),
      store.recordVerification(ownerId, created.id, created.verificationToken, LATER),
    ]);
    expect(a?.verifiedAt).toEqual(b?.verifiedAt);
    expect([FIRST.getTime(), LATER.getTime()]).toContain(a?.verifiedAt?.getTime());
  });
});
