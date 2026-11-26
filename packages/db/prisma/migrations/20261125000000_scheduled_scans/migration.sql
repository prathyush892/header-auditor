-- Scheduled scans (roadmap step 16).

-- AlterTable
ALTER TABLE "sites" ADD COLUMN "next_scan_at" TIMESTAMPTZ(3);

-- CreateIndex
CREATE INDEX "sites_next_scan_at_idx" ON "sites"("next_scan_at");

-- ---------------------------------------------------------------------------
-- Hand-written (see prisma/migrations/README.md)
-- ---------------------------------------------------------------------------

-- Sites that were already on a schedule become due now, so the constraint
-- below holds for existing rows.
UPDATE "sites" SET "next_scan_at" = CURRENT_TIMESTAMP WHERE "schedule" <> 'NONE';

-- A site has a next run exactly when it has a schedule. Written as two
-- implications rather than "(a) = (b)" so neither side can be NULL.
ALTER TABLE "sites" ADD CONSTRAINT "sites_next_scan_at_matches_schedule_check"
    CHECK (
        ("schedule" = 'NONE' AND "next_scan_at" IS NULL)
        OR ("schedule" <> 'NONE' AND "next_scan_at" IS NOT NULL)
    );
