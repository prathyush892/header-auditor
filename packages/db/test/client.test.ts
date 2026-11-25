/**
 * End-to-end: the generated Prisma Client, through createPrismaClient() and
 * the node-postgres adapter, against the migrated database on 127.0.0.1.
 * If schema.prisma and migration.sql ever drift (a renamed column, a missing
 * enum value, a wrong type), these queries fail.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  createPrismaClient,
  findingRows,
  Prisma,
  type PrismaClient,
  toDbGrade,
  toDbScore,
} from "../src/index.js";
import { startTestDatabase, type TestDatabase } from "./helpers/test-database.js";

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
function unique(prefix: string): string {
  counter += 1;
  return `${prefix}${String(counter)}`;
}

async function createUser(): Promise<{ id: string }> {
  return prisma.user.create({
    data: { email: `${unique("user")}@example.test`, passwordHash: "$argon2id$v=19$placeholder" },
    select: { id: true },
  });
}

async function createSite(ownerId: string, url = "https://example.test") {
  return prisma.site.create({
    data: { ownerId, name: "Example", url, verificationToken: unique("t".repeat(40)) },
  });
}

function knownError(error: unknown): Prisma.PrismaClientKnownRequestError {
  expect(error).toBeInstanceOf(Prisma.PrismaClientKnownRequestError);
  return error as Prisma.PrismaClientKnownRequestError;
}

describe("Prisma Client against the migrated schema", () => {
  it("creates a user with defaults filled in by the database and client", async () => {
    const user = await prisma.user.create({
      data: { email: "defaults@example.test", passwordHash: "$argon2id$v=19$placeholder" },
    });
    expect(user.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(user.createdAt).toBeInstanceOf(Date);
    expect(user.updatedAt).toBeInstanceOf(Date);
  });

  it("stores a site with schedule default and first-party host list", async () => {
    const { id } = await createUser();
    const site = await prisma.site.create({
      data: {
        ownerId: id,
        name: "Docs",
        url: "https://docs.example.test",
        verificationToken: unique("v".repeat(40)),
        firstPartyHosts: ["cdn.example.test"],
      },
    });
    expect(site.schedule).toBe("NONE");
    expect(site.verifiedAt).toBeNull();
    expect(site.firstPartyHosts).toEqual(["cdn.example.test"]);
  });

  it("round-trips a full scan with findings and the JSON report", async () => {
    const { id: ownerId } = await createUser();
    const site = await createSite(ownerId);
    const rows = findingRows([
      [
        "HEADERS",
        [
          {
            check: "Strict-Transport-Security",
            status: "pass",
            detail: "max-age=63072000; includeSubDomains",
            weight: 15,
            score: 15,
            recommendation: "",
          },
          {
            check: "Content-Security-Policy",
            status: "fail",
            detail: "Header missing",
            weight: 25,
            score: 0,
            recommendation: "Add a Content-Security-Policy",
          },
        ],
      ],
      [
        "TLS",
        [
          {
            check: "TLS protocol",
            status: "pass",
            detail: "TLSv1.3",
            weight: 10,
            score: 10,
            recommendation: "",
          },
        ],
      ],
    ]);
    const startedAt = new Date("2026-11-20T12:00:00.000Z");
    const scan = await prisma.scan.create({
      data: {
        siteId: site.id,
        status: "SUCCEEDED",
        requestedUrl: "https://example.test/",
        finalUrl: "https://example.test/",
        httpStatus: 200,
        score: toDbScore(50),
        grade: toDbGrade("D"),
        engineVersion: "0.0.0",
        report: { tls: { protocol: "TLSv1.3" }, notes: ["ok"] },
        startedAt,
        finishedAt: new Date(startedAt.getTime() + 1234),
        findings: { createMany: { data: rows } },
      },
    });

    const stored = await prisma.scan.findUniqueOrThrow({
      where: { id: scan.id },
      include: { findings: { orderBy: { position: "asc" } } },
    });
    expect(stored).toMatchObject({
      status: "SUCCEEDED",
      trigger: "MANUAL",
      score: 50,
      grade: "D",
      httpStatus: 200,
      report: { tls: { protocol: "TLSv1.3" }, notes: ["ok"] },
      startedAt,
    });
    expect(
      stored.findings.map((f) => [f.position, f.category, f.check, f.status, f.score]),
    ).toEqual([
      [0, "HEADERS", "Strict-Transport-Security", "PASS", 15],
      [1, "HEADERS", "Content-Security-Policy", "FAIL", 0],
      [2, "TLS", "TLS protocol", "PASS", 10],
    ]);
  });

  it("returns scan history newest first, scoped to one site", async () => {
    const { id: ownerId } = await createUser();
    const site = await createSite(ownerId, "https://history.example.test");
    const other = await createSite(ownerId, "https://other.example.test");
    const base = Date.parse("2026-11-01T00:00:00Z");
    for (let day = 0; day < 5; day += 1) {
      await prisma.scan.create({
        data: {
          siteId: site.id,
          requestedUrl: site.url,
          createdAt: new Date(base + day * 86_400_000),
          // History is finished scans; only one may be queued at a time per site.
          status: "FAILED",
          error: "connection refused",
          finishedAt: new Date(base + day * 86_400_000),
        },
      });
    }
    await prisma.scan.create({ data: { siteId: other.id, requestedUrl: other.url } });

    const page = await prisma.scan.findMany({
      where: { siteId: site.id },
      orderBy: { createdAt: "desc" },
      take: 3,
      select: { createdAt: true },
    });
    expect(page.map((s) => s.createdAt.toISOString().slice(0, 10))).toEqual([
      "2026-11-05",
      "2026-11-04",
      "2026-11-03",
    ]);
  });

  it("only returns sites belonging to the querying owner", async () => {
    const alice = await createUser();
    const bob = await createUser();
    await createSite(alice.id, "https://alice.example.test");
    await createSite(bob.id, "https://bob.example.test");
    const sites = await prisma.site.findMany({
      where: { ownerId: alice.id },
      select: { url: true },
    });
    expect(sites).toEqual([{ url: "https://alice.example.test" }]);
  });

  it("reports a duplicate email as P2002 on the email column", async () => {
    await prisma.user.create({
      data: { email: "dup@example.test", passwordHash: "$argon2id$v=19$placeholder" },
    });
    const error = await prisma.user
      .create({ data: { email: "dup@example.test", passwordHash: "$argon2id$v=19$placeholder" } })
      .then(
        () => undefined,
        (e: unknown) => e,
      );
    expect(knownError(error).code).toBe("P2002");
  });

  it("surfaces a CHECK violation instead of storing an impossible row", async () => {
    const { id: ownerId } = await createUser();
    const site = await createSite(ownerId, "https://check.example.test");
    await expect(
      prisma.scan.create({
        data: { siteId: site.id, requestedUrl: site.url, status: "SUCCEEDED" },
      }),
    ).rejects.toThrow(/scans_succeeded_has_result_check/);
  });

  it("cascades a site delete to its scans and findings", async () => {
    const { id: ownerId } = await createUser();
    const site = await createSite(ownerId, "https://cascade.example.test");
    const scan = await prisma.scan.create({
      data: {
        siteId: site.id,
        requestedUrl: site.url,
        findings: {
          createMany: {
            data: findingRows([
              [
                "DNS",
                [
                  {
                    check: "CAA",
                    status: "warn",
                    detail: "No CAA record",
                    weight: 5,
                    score: 2,
                    recommendation: "Publish a CAA record",
                  },
                ],
              ],
            ]),
          },
        },
      },
    });
    await prisma.site.delete({ where: { id: site.id } });
    expect(await prisma.scan.findUnique({ where: { id: scan.id } })).toBeNull();
    expect(await prisma.finding.count({ where: { scanId: scan.id } })).toBe(0);
  });

  it("updates updatedAt on writes", async () => {
    const { id } = await createUser();
    const before = await prisma.user.findUniqueOrThrow({ where: { id } });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const after = await prisma.user.update({
      where: { id },
      data: { passwordHash: "$argon2id$v=19$rotated" },
    });
    expect(after.updatedAt.getTime()).toBeGreaterThan(before.updatedAt.getTime());
  });
});
