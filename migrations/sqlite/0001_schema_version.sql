-- Fortress migration 0001: schema version tracking table (SQLite)
CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version INTEGER NOT NULL,
  applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT INTO fortress_schema_version (id, version, applied_at)
VALUES (1, 1, unixepoch())
ON CONFLICT(id) DO UPDATE SET version = max(fortress_schema_version.version, excluded.version), applied_at = excluded.applied_at;
