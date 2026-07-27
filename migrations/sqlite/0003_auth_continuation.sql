-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: sqlite
-- version: 0003
-- name: auth_continuation
-- direction: up

CREATE TABLE fortress_refresh_token_v3 (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  token_family TEXT NOT NULL,
  family_created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  successor_token_hash TEXT,
  rotated_at INTEGER,
  is_revoked INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  device_name TEXT,
  last_active_at INTEGER,
  fingerprint_hash TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
INSERT INTO fortress_refresh_token_v3 (
  id, user_id, token_hash, token_family, family_created_at,
  successor_token_hash, rotated_at, is_revoked, expires_at, ip_address,
  user_agent, device_name, last_active_at, fingerprint_hash, created_at
)
SELECT
  token.id, token.user_id, token.token_hash, token.token_family,
  (SELECT MIN(family.created_at)
   FROM fortress_refresh_token AS family
   WHERE family.token_family = token.token_family),
  NULL, NULL, token.is_revoked, token.expires_at, token.ip_address,
  token.user_agent, token.device_name, token.last_active_at,
  token.fingerprint_hash, token.created_at
FROM fortress_refresh_token AS token;
DROP TABLE fortress_refresh_token;
ALTER TABLE fortress_refresh_token_v3 RENAME TO fortress_refresh_token;

CREATE TABLE fortress_auth_continuation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  reason TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
