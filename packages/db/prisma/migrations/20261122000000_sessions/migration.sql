-- CreateTable
CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "token_hash" CHAR(64) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "user_agent" VARCHAR(255),

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "sessions_token_hash_key" ON "sessions"("token_hash");

-- CreateIndex
CREATE INDEX "sessions_user_id_idx" ON "sessions"("user_id");

-- CreateIndex
CREATE INDEX "sessions_expires_at_idx" ON "sessions"("expires_at");

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Hand-written constraints (see prisma/migrations/README.md)
-- ---------------------------------------------------------------------------

-- The API only ever stores a hex SHA-256 here. Anything else (a raw token
-- written by mistake, an upper-case digest that would never match a lookup)
-- is rejected by the database itself.
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_token_hash_format_check"
    CHECK ("token_hash" ~ '^[0-9a-f]{64}$');

ALTER TABLE "sessions" ADD CONSTRAINT "sessions_expiry_order_check"
    CHECK ("expires_at" > "created_at");
