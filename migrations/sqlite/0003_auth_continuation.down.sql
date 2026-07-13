-- Fortress migration 0003 rollback: auth continuation + refresh-session metadata (SQLite)

DROP TABLE IF EXISTS fortress_auth_continuation;
CREATE TABLE fortress_refresh_token_v2 (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  token_family TEXT NOT NULL,
  is_revoked INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  device_name TEXT,
  last_active_at INTEGER,
  fingerprint_hash TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
INSERT INTO fortress_refresh_token_v2 (
  id, user_id, token_hash, token_family, is_revoked, expires_at,
  ip_address, user_agent, device_name, last_active_at, fingerprint_hash, created_at
)
SELECT
  id, user_id, token_hash, token_family, is_revoked, expires_at,
  ip_address, user_agent, device_name, last_active_at, fingerprint_hash, created_at
FROM fortress_refresh_token;
DROP TABLE fortress_refresh_token;
ALTER TABLE fortress_refresh_token_v2 RENAME TO fortress_refresh_token;
