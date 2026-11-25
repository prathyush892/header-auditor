-- Scan queue (roadmap step 15). No generated changes: the scans table from
-- the init migration already has every column the API and worker need.

-- ---------------------------------------------------------------------------
-- Hand-written constraints (see prisma/migrations/README.md)
-- ---------------------------------------------------------------------------

-- At most one queued or running scan per site. The API also checks this
-- inside a transaction, but the index is what makes it impossible to break,
-- whatever the isolation level or however many API instances are running.
-- Prisma can't model partial indexes; migration.test.ts asserts it exists so
-- a generated migration that drops it fails CI.
CREATE UNIQUE INDEX "scans_one_active_per_site_key"
    ON "scans" ("site_id")
    WHERE "status" IN ('QUEUED', 'RUNNING');

-- A running scan always records when it was claimed; the worker uses
-- started_at as the lease token when it writes the result.
ALTER TABLE "scans" ADD CONSTRAINT "scans_running_has_started_at_check"
    CHECK ("status" <> 'RUNNING' OR "started_at" IS NOT NULL);
