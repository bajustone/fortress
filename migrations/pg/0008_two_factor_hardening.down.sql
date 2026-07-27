-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: pg
-- version: 0008
-- name: two_factor_hardening
-- direction: down

DROP INDEX IF EXISTS auth_continuation_failure_idx;
ALTER TABLE fortress_auth_continuation DROP COLUMN cooldown_seconds, DROP COLUMN max_attempts, DROP COLUMN invalidated_at, DROP COLUMN last_failed_at, DROP COLUMN failed_attempts;
