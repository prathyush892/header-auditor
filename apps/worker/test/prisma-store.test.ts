/**
 * The worker store on real SQL (PGlite): claim, lease fencing, result writes
 * and the CHECK constraints they have to satisfy.
 */
import { createPrismaClient, type PrismaClient } from "@header-auditor/db";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { createPrismaWorkerStore } from "../src/prisma-store.js";
import type { ScanSuccess, WorkerScanStore } from "../src/store.js";
import { startTestDatabase, type TestDatabase } from "./helpers/database.js";

let testDb: TestDatabase;
let prisma: PrismaClient;
let store: WorkerScanStore;
let siteId: string;
let counter = 0;

const T0 = new Date("2026-11-24T12:00:00.000Z");
const at = (seconds: number) => new Date(T0.getTime() + seconds * 1_000);

beforeAll(async () => {
  testDb = await startTestDatabase();
  expect(new URL(testDb.url).hostname).toBe("127.0.0.1");
  prisma = createPrismaClient({ databaseUrl: testDb.url, maxConnections: 4 });
  store = createPrismaWorkerStore(prisma);
});

afterAll(async () => {
  await prisma.$disconnect();
  await testDb.stop();
});

beforeEach(async () => {
  counter += 1;
  const user = await prisma.user.create({
    data: { email: `worker${String(counter)}@example.test`, passwordHash: "x" },
  });
  const site = await prisma.site.create({
    data: {
      ownerId: user.id,
      name: "Shop",
      url: `https://shop${String(counter)}.example.com`,
      verificationToken: `${"a".repeat(56)}${String(counter).padStart(8, "0")}`,
      firstPartyHosts: ["cdn.example.net"],
    },
  });
  siteId = site.id;
});

async function queued(): Promise<string> {
  const scan = await prisma.scan.create({
    data: { siteId, requestedUrl: `https://shop${String(counter)}.example.com` },
  });
  return scan.id;
}

const SUCCESS: ScanSuccess = {
  finalUrl: "https://shop.example.com/",
  httpStatus: 200,
  score: 87,
  grade: "B",
  engineVersion: "0.0.0",
  report: { headers: { score: 87 }, tls: { status: "skipped", reason: "x" } },
  findings: [
    {
      category: "HEADERS",
      check: "Strict-Transport-Security",
      status: "PASS",
      detail: "ok",
      weight: 15,
      score: 15,
      recommendation: "",
      position: 0,
    },
    {
      category: "TLS",
      check: "TLS protocol",
      status: "WARN",
      detail: "TLS 1.2",
      weight: 10,
      score: 5,
      recommendation: "Enable TLS 1.3",
      position: 1,
    },
  ],
};

describe("createPrismaWorkerStore", () => {
  it("claims a queued scan once and returns the site's first-party hosts", async () => {
    const id = await queued();
    const claim = await store.claimScan(id, at(0), at(-300));
    expect(claim).toMatchObject({ scanId: id, siteId, firstPartyHosts: ["cdn.example.net"] });
    expect(claim?.startedAt.getTime()).toBe(at(0).getTime());
    // A second delivery of the same job finds it RUNNING and fresh.
    expect(await store.claimScan(id, at(1), at(-299))).toBeNull();
  });

  it("writes the result and findings in one go", async () => {
    const id = await queued();
    const claim = await store.claimScan(id, at(0), at(-300));
    if (claim === null) throw new Error("not claimed");
    expect(await store.completeScan(claim, SUCCESS, at(3))).toBe(true);
    const row = await prisma.scan.findUniqueOrThrow({
      where: { id },
      include: { findings: { orderBy: { position: "asc" } } },
    });
    expect(row).toMatchObject({
      status: "SUCCEEDED",
      score: 87,
      grade: "B",
      httpStatus: 200,
      finalUrl: "https://shop.example.com/",
      engineVersion: "0.0.0",
      error: null,
      report: SUCCESS.report,
    });
    expect(row.finishedAt?.getTime()).toBe(at(3).getTime());
    expect(row.findings.map((f) => [f.category, f.check, f.position])).toEqual([
      ["HEADERS", "Strict-Transport-Security", 0],
      ["TLS", "TLS protocol", 1],
    ]);
  });

  it("re-claims a stale RUNNING scan and fences out the old lease", async () => {
    const id = await queued();
    const old = await store.claimScan(id, at(0), at(-300));
    const fresh = await store.claimScan(id, at(400), at(100));
    if (old === null || fresh === null) throw new Error("not claimed");
    expect(await store.completeScan(old, SUCCESS, at(401))).toBe(false);
    expect(await store.failScan(old, "late", at(401))).toBe(false);
    expect(await store.releaseScan(old)).toBe(false);
    expect(await prisma.finding.count({ where: { scanId: id } })).toBe(0);
    expect(await store.failScan(fresh, "The site did not respond in time.", at(402))).toBe(true);
    expect(await prisma.scan.findUniqueOrThrow({ where: { id } })).toMatchObject({
      status: "FAILED",
      error: "The site did not respond in time.",
    });
  });

  it("rolls the status back if the findings can't be written", async () => {
    const id = await queued();
    const claim = await store.claimScan(id, at(0), at(-300));
    if (claim === null) throw new Error("not claimed");
    const duplicate = {
      ...SUCCESS,
      findings: [SUCCESS.findings[0], SUCCESS.findings[0]],
    } as ScanSuccess;
    await expect(store.completeScan(claim, duplicate, at(1))).rejects.toThrow();
    expect(await prisma.scan.findUniqueOrThrow({ where: { id } })).toMatchObject({
      status: "RUNNING",
      score: null,
    });
  });

  it("releases a claimed scan back to QUEUED for a retry", async () => {
    const id = await queued();
    const claim = await store.claimScan(id, at(0), at(-300));
    if (claim === null) throw new Error("not claimed");
    expect(await store.releaseScan(claim)).toBe(true);
    expect(await prisma.scan.findUniqueOrThrow({ where: { id } })).toMatchObject({
      status: "QUEUED",
      startedAt: null,
    });
    expect(await store.claimScan(id, at(5), at(-295))).not.toBeNull();
  });

  it("abandons queued and running scans but leaves finished ones alone", async () => {
    const id = await queued();
    expect(await store.abandonScan(id, "gave up", at(10))).toBe(true);
    expect(await store.abandonScan(id, "again", at(11))).toBe(false);
    expect(await prisma.scan.findUniqueOrThrow({ where: { id } })).toMatchObject({
      status: "FAILED",
      error: "gave up",
    });
  });

  it("keeps finished_at >= started_at even if this host's clock is behind", async () => {
    const id = await queued();
    const claim = await store.claimScan(id, at(10), at(-290));
    if (claim === null) throw new Error("not claimed");
    expect(await store.failScan(claim, "x", at(5))).toBe(true);
    const row = await prisma.scan.findUniqueOrThrow({ where: { id } });
    expect(row.finishedAt?.getTime()).toBe(at(10).getTime());
  });

  it("returns null for a scan whose site was deleted", async () => {
    const id = await queued();
    await prisma.site.delete({ where: { id: siteId } });
    expect(await store.claimScan(id, at(0), at(-300))).toBeNull();
  });
});
