-- CreateEnum
CREATE TYPE "Grade" AS ENUM ('A', 'B', 'C', 'D', 'F');

-- CreateEnum
CREATE TYPE "FindingStatus" AS ENUM ('PASS', 'WARN', 'FAIL', 'INFO');

-- CreateEnum
CREATE TYPE "FindingCategory" AS ENUM ('HEADERS', 'TLS', 'CONTENT', 'DNS', 'WELL_KNOWN');

-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED');

-- CreateEnum
CREATE TYPE "ScanTrigger" AS ENUM ('MANUAL', 'SCHEDULED');

-- CreateEnum
CREATE TYPE "ScanSchedule" AS ENUM ('NONE', 'DAILY', 'WEEKLY');

-- CreateEnum
CREATE TYPE "AlertKind" AS ENUM ('GRADE_DROP', 'CERT_EXPIRY');

-- CreateEnum
CREATE TYPE "AlertChannel" AS ENUM ('EMAIL', 'WEBHOOK');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "email" VARCHAR(254) NOT NULL,
    "password_hash" VARCHAR(255) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sites" (
    "id" UUID NOT NULL,
    "owner_id" UUID NOT NULL,
    "name" VARCHAR(100) NOT NULL,
    "url" VARCHAR(2048) NOT NULL,
    "verification_token" VARCHAR(64) NOT NULL,
    "verified_at" TIMESTAMPTZ(3),
    "schedule" "ScanSchedule" NOT NULL DEFAULT 'NONE',
    "first_party_hosts" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "sites_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scans" (
    "id" UUID NOT NULL,
    "site_id" UUID NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'QUEUED',
    "trigger" "ScanTrigger" NOT NULL DEFAULT 'MANUAL',
    "requested_url" VARCHAR(2048) NOT NULL,
    "final_url" VARCHAR(2048),
    "http_status" SMALLINT,
    "score" SMALLINT,
    "grade" "Grade",
    "engine_version" VARCHAR(32),
    "report" JSONB,
    "error" VARCHAR(500),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "started_at" TIMESTAMPTZ(3),
    "finished_at" TIMESTAMPTZ(3),

    CONSTRAINT "scans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "findings" (
    "id" UUID NOT NULL,
    "scan_id" UUID NOT NULL,
    "category" "FindingCategory" NOT NULL,
    "check" VARCHAR(100) NOT NULL,
    "status" "FindingStatus" NOT NULL,
    "detail" TEXT NOT NULL,
    "weight" SMALLINT NOT NULL,
    "score" SMALLINT NOT NULL,
    "recommendation" TEXT NOT NULL DEFAULT '',
    "position" SMALLINT NOT NULL,

    CONSTRAINT "findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "alert_rules" (
    "id" UUID NOT NULL,
    "site_id" UUID NOT NULL,
    "kind" "AlertKind" NOT NULL,
    "channel" "AlertChannel" NOT NULL,
    "target" VARCHAR(2048) NOT NULL,
    "cert_expiry_days" SMALLINT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "last_triggered_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "alert_rules_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "sites_verification_token_key" ON "sites"("verification_token");

-- CreateIndex
CREATE INDEX "sites_owner_id_created_at_idx" ON "sites"("owner_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "sites_owner_id_url_key" ON "sites"("owner_id", "url");

-- CreateIndex
CREATE INDEX "scans_site_id_created_at_idx" ON "scans"("site_id", "created_at" DESC);

-- CreateIndex
CREATE INDEX "scans_status_idx" ON "scans"("status");

-- CreateIndex
CREATE INDEX "findings_scan_id_check_idx" ON "findings"("scan_id", "check");

-- CreateIndex
CREATE UNIQUE INDEX "findings_scan_id_position_key" ON "findings"("scan_id", "position");

-- CreateIndex
CREATE INDEX "alert_rules_site_id_idx" ON "alert_rules"("site_id");

-- CreateIndex
CREATE UNIQUE INDEX "alert_rules_site_id_kind_channel_target_key" ON "alert_rules"("site_id", "kind", "channel", "target");

-- AddForeignKey
ALTER TABLE "sites" ADD CONSTRAINT "sites_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scans" ADD CONSTRAINT "scans_site_id_fkey" FOREIGN KEY ("site_id") REFERENCES "sites"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alert_rules" ADD CONSTRAINT "alert_rules_site_id_fkey" FOREIGN KEY ("site_id") REFERENCES "sites"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Hand-written constraints (not expressible in schema.prisma).
-- Prisma Migrate leaves CHECK constraints alone when diffing, so these survive
-- future generated migrations. Each one mirrors an invariant the application
-- already enforces, so a bug in one layer can't write an impossible row.
-- ---------------------------------------------------------------------------

-- Emails are normalised before insert; this makes "Alice@x" and "alice@x"
-- collide on users_email_key instead of creating two accounts.
ALTER TABLE "users" ADD CONSTRAINT "users_email_lowercase_check"
    CHECK ("email" = lower("email"));

-- Tokens come from 32 random bytes (hex or base64url), never short guessable values.
ALTER TABLE "sites" ADD CONSTRAINT "sites_verification_token_length_check"
    CHECK (char_length("verification_token") >= 32);

-- Only http(s) origins can be stored as scan targets.
ALTER TABLE "sites" ADD CONSTRAINT "sites_url_scheme_check"
    CHECK ("url" ~ '^https?://');

ALTER TABLE "scans" ADD CONSTRAINT "scans_score_range_check"
    CHECK ("score" IS NULL OR "score" BETWEEN 0 AND 100);

ALTER TABLE "scans" ADD CONSTRAINT "scans_http_status_range_check"
    CHECK ("http_status" IS NULL OR "http_status" BETWEEN 100 AND 599);

-- A succeeded scan always has a result; a failed one always says why.
ALTER TABLE "scans" ADD CONSTRAINT "scans_succeeded_has_result_check"
    CHECK ("status" <> 'SUCCEEDED' OR ("score" IS NOT NULL AND "grade" IS NOT NULL AND "finished_at" IS NOT NULL));

ALTER TABLE "scans" ADD CONSTRAINT "scans_failed_has_error_check"
    CHECK ("status" <> 'FAILED' OR ("error" IS NOT NULL AND "finished_at" IS NOT NULL));

ALTER TABLE "scans" ADD CONSTRAINT "scans_timestamps_order_check"
    CHECK ("started_at" IS NULL OR "finished_at" IS NULL OR "finished_at" >= "started_at");

-- Same scoring invariant as makeFinding() in packages/core.
ALTER TABLE "findings" ADD CONSTRAINT "findings_score_range_check"
    CHECK ("weight" >= 0 AND "score" >= 0 AND "score" <= "weight");

ALTER TABLE "findings" ADD CONSTRAINT "findings_position_check"
    CHECK ("position" >= 0);

-- cert_expiry_days is required for CERT_EXPIRY rules and forbidden otherwise.
-- The explicit IS NOT NULL matters: a CHECK only fails on FALSE, and
-- "NULL BETWEEN 1 AND 365" is NULL, which would let a missing value through.
ALTER TABLE "alert_rules" ADD CONSTRAINT "alert_rules_cert_expiry_days_check"
    CHECK (
        ("kind" = 'CERT_EXPIRY' AND "cert_expiry_days" IS NOT NULL AND "cert_expiry_days" BETWEEN 1 AND 365)
        OR ("kind" <> 'CERT_EXPIRY' AND "cert_expiry_days" IS NULL)
    );
