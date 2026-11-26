/**
 * Applies the committed migration to a real (WASM) Postgres and checks the
 * schema the database actually ends up with: enums match the generated
 * client, every hand-written CHECK constraint rejects what it should, and
 * deletes cascade down the ownership chain.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { PGlite } from "@electric-sql/pglite";

import {
  AlertChannel,
  AlertKind,
  FindingCategory,
  FindingStatus,
  Grade,
  ScanSchedule,
  ScanStatus,
  ScanTrigger,
} from "../src/index.js";
import { applyMigrations, migrationNames, readMigration } from "./helpers/test-database.js";

let db: PGlite;

beforeAll(async () => {
  db = await PGlite.create();
  await applyMigrations(db);
});

afterAll(async () => {
  await db.close();
});

const TOKEN = "a".repeat(64);

function firstRow<T>(rows: readonly T[]): T {
  const [row] = rows;
  if (row === undefined) throw new Error("query returned no rows");
  return row;
}
let counter = 0;

async function insertUser(email = `user${String(++counter)}@example.test`): Promise<string> {
  const { rows } = await db.query<{ id: string }>(
    `INSERT INTO users (id, email, password_hash, updated_at)
     VALUES (gen_random_uuid(), $1, 'argon2id-placeholder', now()) RETURNING id`,
    [email],
  );
  return firstRow(rows).id;
}

async function insertSite(ownerId: string, url = "https://example.test"): Promise<string> {
  const { rows } = await db.query<{ id: string }>(
    `INSERT INTO sites (id, owner_id, name, url, verification_token, updated_at)
     VALUES (gen_random_uuid(), $1, 'Example', $2, $3, now()) RETURNING id`,
    [ownerId, url, `${TOKEN.slice(0, 60)}${String(++counter).padStart(4, "0")}`],
  );
  return firstRow(rows).id;
}

async function insertScan(siteId: string, columns: Record<string, unknown> = {}): Promise<string> {
  const values = { requested_url: "https://example.test/", ...columns };
  const names = Object.keys(values);
  const placeholders = names.map((_, i) => `$${String(i + 2)}`);
  const { rows } = await db.query<{ id: string }>(
    `INSERT INTO scans (id, site_id, ${names.map((n) => `"${n}"`).join(", ")})
     VALUES (gen_random_uuid(), $1, ${placeholders.join(", ")}) RETURNING id`,
    [siteId, ...Object.values(values)],
  );
  return firstRow(rows).id;
}

async function count(table: string): Promise<number> {
  const { rows } = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${table}"`);
  return firstRow(rows).n;
}

describe("migration files", () => {
  it("has a single initial migration with a sortable timestamp prefix", async () => {
    const names = await migrationNames();
    expect(names.length).toBeGreaterThanOrEqual(1);
    for (const name of names) expect(name).toMatch(/^\d{14}_[a-z0-9_]+$/);
    expect(names[0]).toMatch(/_init$/);
  });

  it("creates the six tables", async () => {
    const { rows } = await db.query<{ table_name: string }>(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = 'public' ORDER BY table_name`,
    );
    expect(rows.map((r) => r.table_name)).toEqual([
      "alert_rules",
      "findings",
      "scans",
      "sessions",
      "sites",
      "users",
    ]);
  });

  it("creates Postgres enums identical to the generated client's enums", async () => {
    const { rows } = await db.query<{ name: string; labels: string[] }>(
      `SELECT t.typname AS name, array_agg(e.enumlabel ORDER BY e.enumsortorder) AS labels
       FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid
       GROUP BY t.typname`,
    );
    const actual = Object.fromEntries(rows.map((r) => [r.name, r.labels]));
    expect(actual).toEqual({
      Grade: Object.values(Grade),
      FindingStatus: Object.values(FindingStatus),
      FindingCategory: Object.values(FindingCategory),
      ScanStatus: Object.values(ScanStatus),
      ScanTrigger: Object.values(ScanTrigger),
      ScanSchedule: Object.values(ScanSchedule),
      AlertKind: Object.values(AlertKind),
      AlertChannel: Object.values(AlertChannel),
    });
  });

  it("indexes scan history by site, newest first", async () => {
    const { rows } = await db.query<{ indexdef: string }>(
      `SELECT indexdef FROM pg_indexes WHERE indexname = 'scans_site_id_created_at_idx'`,
    );
    expect(rows[0]?.indexdef).toMatch(/\(site_id, created_at DESC\)/);
  });

  it("makes every foreign key ON DELETE CASCADE", async () => {
    const { rows } = await db.query<{ conname: string; confdeltype: string }>(
      `SELECT conname, confdeltype FROM pg_constraint WHERE contype = 'f' ORDER BY conname`,
    );
    expect(rows).toEqual([
      { conname: "alert_rules_site_id_fkey", confdeltype: "c" },
      { conname: "findings_scan_id_fkey", confdeltype: "c" },
      { conname: "scans_site_id_fkey", confdeltype: "c" },
      { conname: "sessions_user_id_fkey", confdeltype: "c" },
      { conname: "sites_owner_id_fkey", confdeltype: "c" },
    ]);
  });
});

describe("CHECK constraints", () => {
  it("rejects a mixed-case email so lower-casing can't be skipped", async () => {
    await expect(insertUser("Alice@Example.test")).rejects.toThrow(/users_email_lowercase_check/);
    await expect(insertUser("alice@example.test")).resolves.toBeTypeOf("string");
    await expect(insertUser("alice@example.test")).rejects.toThrow(/users_email_key/);
  });

  it("rejects short verification tokens and non-http(s) site URLs", async () => {
    const owner = await insertUser();
    await expect(
      db.query(
        `INSERT INTO sites (id, owner_id, name, url, verification_token, updated_at)
         VALUES (gen_random_uuid(), $1, 'x', 'https://a.test', 'short', now())`,
        [owner],
      ),
    ).rejects.toThrow(/sites_verification_token_length_check/);
    await expect(insertSite(owner, "file:///etc/passwd")).rejects.toThrow(/sites_url_scheme_check/);
    await expect(insertSite(owner, "javascript:alert(1)")).rejects.toThrow(
      /sites_url_scheme_check/,
    );
  });

  it("allows the same URL for two owners but not twice for one owner", async () => {
    const a = await insertUser();
    const b = await insertUser();
    await insertSite(a, "https://shared.test");
    await expect(insertSite(b, "https://shared.test")).resolves.toBeTypeOf("string");
    await expect(insertSite(a, "https://shared.test")).rejects.toThrow(/sites_owner_id_url_key/);
  });

  describe("scans", () => {
    let site: string;
    beforeAll(async () => {
      site = await insertSite(await insertUser());
    });

    it.each([
      [{ score: 101 }, "scans_score_range_check"],
      [{ score: -1 }, "scans_score_range_check"],
      [{ http_status: 99 }, "scans_http_status_range_check"],
      [{ http_status: 600 }, "scans_http_status_range_check"],
      [{ status: "SUCCEEDED", score: 90 }, "scans_succeeded_has_result_check"],
      [{ status: "FAILED", finished_at: new Date() }, "scans_failed_has_error_check"],
      [
        {
          started_at: new Date("2026-11-20T10:00:00Z"),
          finished_at: new Date("2026-11-20T09:59:59Z"),
        },
        "scans_timestamps_order_check",
      ],
    ])("rejects %j (%s)", async (columns, constraint) => {
      await expect(insertScan(site, columns)).rejects.toThrow(constraint);
    });

    it("accepts a complete succeeded scan and a failed scan with a reason", async () => {
      const now = new Date();
      await expect(
        insertScan(site, {
          status: "SUCCEEDED",
          score: 92,
          grade: "A",
          http_status: 200,
          started_at: now,
          finished_at: now,
        }),
      ).resolves.toBeTypeOf("string");
      await expect(
        insertScan(site, { status: "FAILED", error: "connection refused", finished_at: now }),
      ).resolves.toBeTypeOf("string");
    });
  });

  describe("findings", () => {
    let scan: string;
    beforeAll(async () => {
      scan = await insertScan(await insertSite(await insertUser()));
    });

    async function insertFinding(weight: number, score: number, position: number): Promise<void> {
      await db.query(
        `INSERT INTO findings (id, scan_id, category, "check", status, detail, weight, score, position)
         VALUES (gen_random_uuid(), $1, 'HEADERS', 'HSTS', 'PASS', '', $2, $3, $4)`,
        [scan, weight, score, position],
      );
    }

    it("enforces 0 <= score <= weight like makeFinding()", async () => {
      await expect(insertFinding(10, 11, 0)).rejects.toThrow(/findings_score_range_check/);
      await expect(insertFinding(10, -1, 0)).rejects.toThrow(/findings_score_range_check/);
      await expect(insertFinding(-1, 0, 0)).rejects.toThrow(/findings_score_range_check/);
      await expect(insertFinding(10, 10, -1)).rejects.toThrow(/findings_position_check/);
    });

    it("keeps positions unique within a scan", async () => {
      await insertFinding(10, 5, 0);
      await expect(insertFinding(10, 5, 0)).rejects.toThrow(/findings_scan_id_position_key/);
    });
  });

  describe("alert rules", () => {
    let site: string;
    beforeAll(async () => {
      site = await insertSite(await insertUser());
    });

    async function insertRule(kind: string, days: number | null, target: string): Promise<void> {
      await db.query(
        `INSERT INTO alert_rules (id, site_id, kind, channel, target, cert_expiry_days, updated_at)
         VALUES (gen_random_uuid(), $1, $2, 'EMAIL', $3, $4, now())`,
        [site, kind, target, days],
      );
    }

    it("requires cert_expiry_days (1-365) only for CERT_EXPIRY", async () => {
      const check = /alert_rules_cert_expiry_days_check/;
      await expect(insertRule("CERT_EXPIRY", null, "a@example.test")).rejects.toThrow(check);
      await expect(insertRule("CERT_EXPIRY", 0, "a@example.test")).rejects.toThrow(check);
      await expect(insertRule("CERT_EXPIRY", 366, "a@example.test")).rejects.toThrow(check);
      await expect(insertRule("GRADE_DROP", 14, "a@example.test")).rejects.toThrow(check);
      await expect(insertRule("CERT_EXPIRY", 14, "a@example.test")).resolves.toBeUndefined();
      await expect(insertRule("GRADE_DROP", null, "a@example.test")).resolves.toBeUndefined();
    });

    it("rejects a duplicate rule for the same target", async () => {
      await expect(insertRule("GRADE_DROP", null, "a@example.test")).rejects.toThrow(
        /alert_rules_site_id_kind_channel_target_key/,
      );
    });
  });
});

describe("sessions", () => {
  const HASH = "0123456789abcdef".repeat(4);

  async function insertSession(
    userId: string,
    tokenHash: string,
    expiresAt = "now() + interval '1 day'",
  ): Promise<void> {
    await db.query(
      `INSERT INTO sessions (id, user_id, token_hash, expires_at)
       VALUES (gen_random_uuid(), $1, $2, ${expiresAt})`,
      [userId, tokenHash],
    );
  }

  it("is a second migration after init", async () => {
    const names = await migrationNames();
    expect(names).toContain("20261122000000_sessions");
    expect(names.indexOf("20261122000000_sessions")).toBeGreaterThan(0);
  });

  it("accepts a lower-case hex SHA-256 and enforces uniqueness", async () => {
    const user = await insertUser();
    await insertSession(user, HASH);
    await expect(insertSession(user, HASH)).rejects.toThrow(/sessions_token_hash_key/);
  });

  it.each([
    ["upper-case hex", "0123456789ABCDEF".repeat(4)],
    ["a raw base64url token", "A".repeat(43) + "-".repeat(21)],
    ["too short", "abc"],
  ])("rejects a token hash that is %s", async (_label, hash) => {
    const user = await insertUser();
    await expect(insertSession(user, hash)).rejects.toThrow(
      /sessions_token_hash_format_check|value too long/,
    );
  });

  it("rejects an expiry that is not after creation", async () => {
    const user = await insertUser();
    await expect(
      insertSession(user, "f".repeat(64), "now() - interval '1 second'"),
    ).rejects.toThrow(/sessions_expiry_order_check/);
  });

  it("deleting a user removes their sessions", async () => {
    const user = await insertUser();
    await insertSession(user, "e".repeat(64));
    const before = await count("sessions");
    await db.query(`DELETE FROM users WHERE id = $1`, [user]);
    expect(await count("sessions")).toBe(before - 1);
  });
});

describe("cascading deletes", () => {
  it("deleting a user removes their sites, scans, findings and alert rules", async () => {
    const keep = await insertSite(await insertUser());
    await insertScan(keep);

    const owner = await insertUser();
    const site = await insertSite(owner);
    const scan = await insertScan(site);
    await db.query(
      `INSERT INTO findings (id, scan_id, category, "check", status, detail, weight, score, position)
       VALUES (gen_random_uuid(), $1, 'TLS', 'TLS protocol', 'PASS', '', 10, 10, 0)`,
      [scan],
    );
    await db.query(
      `INSERT INTO alert_rules (id, site_id, kind, channel, target, updated_at)
       VALUES (gen_random_uuid(), $1, 'GRADE_DROP', 'WEBHOOK', 'https://hooks.example.test/x', now())`,
      [site],
    );

    const before = {
      sites: await count("sites"),
      scans: await count("scans"),
      findings: await count("findings"),
      alerts: await count("alert_rules"),
    };
    await db.query(`DELETE FROM users WHERE id = $1`, [owner]);

    expect(await count("sites")).toBe(before.sites - 1);
    expect(await count("scans")).toBe(before.scans - 1);
    expect(await count("findings")).toBe(before.findings - 1);
    expect(await count("alert_rules")).toBe(before.alerts - 1);
    const { rows } = await db.query(`SELECT 1 FROM sites WHERE id = $1`, [keep]);
    expect(rows).toHaveLength(1);
  });
});

describe("scan queue migration", () => {
  let owner: string;
  beforeAll(async () => {
    owner = await insertUser();
  });

  it("comes after the sessions migration", async () => {
    const names = await migrationNames();
    expect(names.at(-2)).toBe("20261124000000_scan_queue");
  });

  it("declares the one-active-scan-per-site partial unique index", async () => {
    const { rows } = await db.query<{ indexdef: string }>(
      `SELECT indexdef FROM pg_indexes WHERE indexname = 'scans_one_active_per_site_key'`,
    );
    expect(firstRow(rows).indexdef).toMatch(/UNIQUE INDEX .* \(site_id\) WHERE/);
  });

  it("allows one queued or running scan per site, and any number of finished ones", async () => {
    const site = await insertSite(owner, "https://queue-a.example.test");
    const now = new Date();
    await insertScan(site);
    await expect(insertScan(site)).rejects.toThrow("scans_one_active_per_site_key");
    await expect(insertScan(site, { status: "RUNNING", started_at: now })).rejects.toThrow(
      "scans_one_active_per_site_key",
    );
    await insertScan(site, { status: "FAILED", error: "x", finished_at: now });
    await insertScan(site, { status: "FAILED", error: "y", finished_at: now });
    await insertScan(site, {
      status: "SUCCEEDED",
      score: 90,
      grade: "A",
      started_at: now,
      finished_at: now,
    });
  });

  it("scopes the rule to one site", async () => {
    const a = await insertSite(owner, "https://queue-b.example.test");
    const b = await insertSite(owner, "https://queue-c.example.test");
    await insertScan(a);
    await expect(insertScan(b)).resolves.toBeTypeOf("string");
  });

  it("requires started_at on a running scan (the worker's lease token)", async () => {
    const site = await insertSite(owner, "https://queue-d.example.test");
    await expect(insertScan(site, { status: "RUNNING" })).rejects.toThrow(
      "scans_running_has_started_at_check",
    );
  });
});

describe("scheduled scans migration", () => {
  let owner: string;
  beforeAll(async () => {
    owner = await insertUser();
  });

  async function setSchedule(
    siteId: string,
    schedule: string,
    nextScanAt: Date | null,
  ): Promise<void> {
    await db.query(`UPDATE sites SET schedule = $2, next_scan_at = $3 WHERE id = $1`, [
      siteId,
      schedule,
      nextScanAt,
    ]);
  }

  it("is the latest migration, after the scan queue", async () => {
    const names = await migrationNames();
    expect(names.at(-1)).toBe("20261125000000_scheduled_scans");
  });

  it("indexes sites by next_scan_at for the scheduler", async () => {
    const { rows } = await db.query<{ indexdef: string }>(
      `SELECT indexdef FROM pg_indexes WHERE indexname = 'sites_next_scan_at_idx'`,
    );
    expect(firstRow(rows).indexdef).toMatch(/\(next_scan_at\)/);
  });

  it("requires next_scan_at exactly when the site has a schedule", async () => {
    const site = await insertSite(owner, "https://sched-a.example.test");
    const at = new Date();
    await expect(setSchedule(site, "DAILY", null)).rejects.toThrow(
      "sites_next_scan_at_matches_schedule_check",
    );
    await expect(setSchedule(site, "NONE", at)).rejects.toThrow(
      "sites_next_scan_at_matches_schedule_check",
    );
    await setSchedule(site, "DAILY", at);
    await setSchedule(site, "WEEKLY", at);
    await setSchedule(site, "NONE", null);
  });

  it("makes already-scheduled sites due when it is applied", async () => {
    // Replay the migration's backfill on a database that only has the earlier ones.
    const fresh = await PGlite.create();
    try {
      const names = await migrationNames();
      for (const name of names.slice(0, -1)) {
        await fresh.exec(await readMigration(name));
      }
      const { rows: users } = await fresh.query<{ id: string }>(
        `INSERT INTO users (id, email, password_hash, updated_at)
         VALUES (gen_random_uuid(), 'old@example.test', 'x', now()) RETURNING id`,
      );
      await fresh.query(
        `INSERT INTO sites (id, owner_id, name, url, verification_token, schedule, updated_at)
         VALUES (gen_random_uuid(), $1, 'Old', 'https://old.example.test', $2, 'WEEKLY', now()),
                (gen_random_uuid(), $1, 'Off', 'https://off.example.test', $3, 'NONE', now())`,
        [firstRow(users).id, "b".repeat(64), "c".repeat(64)],
      );
      await fresh.exec(await readMigration(names.at(-1) ?? ""));
      const { rows } = await fresh.query<{ schedule: string; due: boolean }>(
        `SELECT schedule, next_scan_at IS NOT NULL AS due FROM sites ORDER BY schedule`,
      );
      expect(rows).toEqual([
        { schedule: "NONE", due: false },
        { schedule: "WEEKLY", due: true },
      ]);
    } finally {
      await fresh.close();
    }
  });
});
