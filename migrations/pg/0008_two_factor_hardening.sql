-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: pg
-- version: 0008
-- name: two_factor_hardening
-- direction: up

ALTER TABLE fortress_auth_continuation
  ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN last_failed_at TIMESTAMPTZ,
  ADD COLUMN invalidated_at TIMESTAMPTZ,
  ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 5,
  ADD COLUMN cooldown_seconds INTEGER NOT NULL DEFAULT 1;
CREATE INDEX auth_continuation_failure_idx ON fortress_auth_continuation (user_id, reason, last_failed_at);
