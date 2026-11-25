# Migrations

Applied in folder order by `prisma migrate deploy` (production, CI) or
`prisma migrate dev` (local, creates new migrations from `schema.prisma`).

## Hand-written SQL

Each `migration.sql` starts with the SQL Prisma generates from the schema.
Anything Prisma can't express goes in a clearly marked block at the end of the
same migration:

- `CHECK` constraints mirroring application invariants (score ranges,
  lower-case emails, "a succeeded scan has a grade", ...).
- Partial indexes, such as `scans_one_active_per_site_key` (one queued or
  running scan per site).

Prisma Migrate doesn't model CHECK constraints, so it neither generates nor
drops them; they survive later generated migrations. Partial indexes are
different: `prisma migrate dev` may propose dropping an index the schema
doesn't declare. Delete that line from the generated SQL; the migration
tests assert the index still exists. When changing a column a
constraint refers to, update the constraint in the same migration.

## Rules

- Never edit a migration that has been applied anywhere shared; add a new one.
- Every constraint gets a test in `packages/db/test/migration.test.ts`.
- Remember SQL's three-valued logic: a `CHECK` only rejects `FALSE`, so a
  condition that evaluates to `NULL` passes. Test the `NULL` case.
