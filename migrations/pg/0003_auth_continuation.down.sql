-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: pg
-- version: 0003
-- name: auth_continuation
-- direction: down

DROP TABLE IF EXISTS fortress_auth_continuation CASCADE;
ALTER TABLE fortress_refresh_token DROP COLUMN rotated_at;
ALTER TABLE fortress_refresh_token DROP COLUMN successor_token_hash;
ALTER TABLE fortress_refresh_token DROP COLUMN family_created_at;
