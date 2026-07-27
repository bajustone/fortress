-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: sqlite
-- version: 0001
-- name: schema_version
-- direction: up

CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version INTEGER NOT NULL,
  applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);
