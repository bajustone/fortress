-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: pg
-- version: 0001
-- name: schema_version
-- direction: up

CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version integer NOT NULL,
  applied_at timestamp NOT NULL DEFAULT now()
);
