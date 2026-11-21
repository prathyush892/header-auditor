/**
 * Throwaway Postgres for tests: PGlite (Postgres compiled to WASM, in-process)
 * with the committed migrations applied, exposed over the Postgres wire
 * protocol on 127.0.0.1 so the real `pg` driver and Prisma adapter connect to
 * it exactly as they would to a server. No Docker or external service needed.
 */
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { PGlite } from "@electric-sql/pglite";
import { PGLiteSocketServer } from "@electric-sql/pglite-socket";

export const MIGRATIONS_DIR = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));

/** Migration folder names in apply order (Prisma sorts them lexically by timestamp prefix). */
export async function migrationNames(): Promise<string[]> {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const entries = await readdir(MIGRATIONS_DIR, { withFileTypes: true });
  return entries
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

export async function applyMigrations(db: PGlite): Promise<string[]> {
  const names = await migrationNames();
  for (const name of names) {
    // Path is built from a directory listing of our own repo, not user input.
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const sql = await readFile(join(MIGRATIONS_DIR, name, "migration.sql"), "utf8");
    await db.exec(sql);
  }
  return names;
}

export interface TestDatabase {
  readonly db: PGlite;
  /** postgres:// URL pointing at the 127.0.0.1 socket server. */
  readonly url: string;
  stop(): Promise<void>;
}

export async function startTestDatabase(): Promise<TestDatabase> {
  const db = await PGlite.create();
  await applyMigrations(db);
  const server = new PGLiteSocketServer({ db, host: "127.0.0.1", port: 0, maxConnections: 4 });
  await server.start();
  const url = `postgres://postgres@${server.getServerConn()}/postgres?sslmode=disable`;
  return {
    db,
    url,
    async stop() {
      await server.stop();
      await db.close();
    },
  };
}
