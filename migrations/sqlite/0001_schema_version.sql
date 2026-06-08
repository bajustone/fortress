-- Fortress migration 0001: schema version tracking table (SQLite)
-- The version row is written by the migration runner after apply; this
-- migration only creates the checkpoint table.
CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version INTEGER NOT NULL,
  applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);
