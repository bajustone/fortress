CREATE TABLE fortress_audit_chain_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  last_hash VARCHAR(64),
  entry_count INTEGER NOT NULL CHECK (entry_count >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((entry_count = 0 AND last_hash IS NULL) OR (entry_count > 0 AND last_hash IS NOT NULL))
);
INSERT INTO fortress_audit_chain_state (id, last_hash, entry_count) VALUES (1, NULL, 0);
