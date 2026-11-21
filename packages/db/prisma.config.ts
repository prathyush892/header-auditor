/**
 * Prisma CLI configuration (Prisma 7 moved the connection URL out of
 * schema.prisma). The datasource is only declared when DATABASE_URL is set,
 * so `prisma generate` and `prisma validate` work in CI without a database,
 * while `migrate deploy` fails fast with Prisma's own "no datasource" error.
 */
import { defineConfig } from "prisma/config";

const url = process.env.DATABASE_URL;

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: { path: "prisma/migrations" },
  ...(url ? { datasource: { url } } : {}),
});
