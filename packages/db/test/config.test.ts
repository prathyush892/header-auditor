import { describe, expect, it } from "vitest";

import {
  createPrismaClient,
  DatabaseConfigError,
  parseDatabaseUrl,
  redactDatabaseUrl,
} from "../src/index.js";

describe("parseDatabaseUrl", () => {
  it("accepts postgres:// and postgresql:// URLs", () => {
    expect(parseDatabaseUrl("postgres://app:pw@127.0.0.1:5432/header_auditor").hostname).toBe(
      "127.0.0.1",
    );
    expect(parseDatabaseUrl("postgresql://app@db/header_auditor?sslmode=require").search).toBe(
      "?sslmode=require",
    );
  });

  it("trims surrounding whitespace (common in copied .env values)", () => {
    expect(parseDatabaseUrl("  postgres://app@db/app\n").pathname).toBe("/app");
  });

  it.each([undefined, "", "   "])("rejects a missing value (%j)", (raw) => {
    expect(() => parseDatabaseUrl(raw)).toThrow(/DATABASE_URL is not set/);
  });

  it("rejects strings that are not URLs", () => {
    expect(() => parseDatabaseUrl("not a url")).toThrow(DatabaseConfigError);
  });

  it.each(["mysql://app@db/app", "http://db/app", "file:./dev.db"])(
    "rejects non-Postgres schemes (%s)",
    (raw) => {
      expect(() => parseDatabaseUrl(raw)).toThrow(/must use postgres/);
    },
  );

  it("requires a host", () => {
    expect(() => parseDatabaseUrl("postgres:///app")).toThrow(/no host/);
  });

  it.each(["postgres://app@db", "postgres://app@db/", "postgres://app@db/a/b"])(
    "requires exactly one database name (%s)",
    (raw) => {
      expect(() => parseDatabaseUrl(raw)).toThrow(/exactly one database/);
    },
  );

  it("never puts the password in an error message", () => {
    const secret = "s3cr3t-value";
    for (const raw of [
      `postgres://app:${secret}@db`,
      `mysql://app:${secret}@db/app`,
      `postgres://app:${secret}@db/a/b`,
      `postgres://app:${secret}@[bad`,
    ]) {
      try {
        parseDatabaseUrl(raw);
        expect.unreachable(`expected ${raw} to be rejected`);
      } catch (error) {
        expect(error).toBeInstanceOf(DatabaseConfigError);
        expect((error as Error).message).not.toContain(secret);
      }
    }
  });
});

describe("redactDatabaseUrl", () => {
  it("masks the password and keeps everything else", () => {
    expect(redactDatabaseUrl("postgres://app:hunter2@db:5432/app?sslmode=require")).toBe(
      "postgres://app:***@db:5432/app?sslmode=require",
    );
  });

  it("leaves password-less URLs unchanged", () => {
    expect(redactDatabaseUrl("postgres://app@db/app")).toBe("postgres://app@db/app");
  });

  it("does not echo unparseable input", () => {
    expect(redactDatabaseUrl("postgres://app:pw@[bad")).toBe("<invalid database url>");
  });
});

describe("createPrismaClient option validation", () => {
  const databaseUrl = "postgres://app@127.0.0.1:5432/app";

  it("validates the URL before creating a pool", () => {
    expect(() => createPrismaClient({ databaseUrl: "mysql://x@y/z" })).toThrow(DatabaseConfigError);
  });

  it.each([0, -1, 1.5, 101, Number.NaN])("rejects maxConnections=%s", (maxConnections) => {
    expect(() => createPrismaClient({ databaseUrl, maxConnections })).toThrow(RangeError);
  });

  it.each([0, 120_001])("rejects connectionTimeoutMs=%s", (connectionTimeoutMs) => {
    expect(() => createPrismaClient({ databaseUrl, connectionTimeoutMs })).toThrow(RangeError);
  });

  it("creates a client lazily without connecting", async () => {
    const client = createPrismaClient({ databaseUrl, maxConnections: 2 });
    expect(typeof client.user.findMany).toBe("function");
    await client.$disconnect();
  });
});
