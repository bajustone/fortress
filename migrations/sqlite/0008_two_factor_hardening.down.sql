-- SQLite cannot drop columns portably; recreate the continuation table without hardening fields.
CREATE TABLE fortress_auth_continuation_old AS SELECT id, user_id, token_hash, reason, expires_at, consumed_at, created_at FROM fortress_auth_continuation;
DROP TABLE fortress_auth_continuation;
CREATE TABLE fortress_auth_continuation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  reason TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
INSERT INTO fortress_auth_continuation SELECT * FROM fortress_auth_continuation_old;
DROP TABLE fortress_auth_continuation_old;
