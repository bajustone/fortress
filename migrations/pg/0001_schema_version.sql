-- Fortress migration 0001: schema version tracking table (PostgreSQL)
CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version integer NOT NULL,
  applied_at timestamp NOT NULL DEFAULT now()
);

INSERT INTO fortress_schema_version (id, version, applied_at)
VALUES (1, 1, now())
ON CONFLICT (id) DO UPDATE SET version = greatest(fortress_schema_version.version, excluded.version), applied_at = excluded.applied_at;
