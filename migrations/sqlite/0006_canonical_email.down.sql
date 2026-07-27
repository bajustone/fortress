-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: sqlite
-- version: 0006
-- name: canonical_email
-- direction: down

-- Canonicalization and duplicate-account quarantine are intentionally irreversible.
DROP INDEX IF EXISTS login_identifier_email_ci_unique;
DROP INDEX IF EXISTS user_email_ci_unique;
