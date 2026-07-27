-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: pg
-- version: 0004
-- name: tenant_default_unique
-- direction: down

DROP INDEX IF EXISTS fortress_tenant_user_one_default_idx;
