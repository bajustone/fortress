-- Fortress migration 0001: schema version tracking table (PostgreSQL)
-- The version row is written by the migration runner after apply; this
-- migration only creates the checkpoint table.
CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version integer NOT NULL,
  applied_at timestamp NOT NULL DEFAULT now()
);
