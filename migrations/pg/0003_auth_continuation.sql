-- Fortress migration 0003: auth continuation + refresh-session metadata (PostgreSQL)

ALTER TABLE fortress_refresh_token
  ADD COLUMN family_created_at TIMESTAMP;
UPDATE fortress_refresh_token AS token
  SET family_created_at = family.created_at
  FROM (
    SELECT token_family, MIN(created_at) AS created_at
    FROM fortress_refresh_token
    GROUP BY token_family
  ) AS family
  WHERE token.token_family = family.token_family;
ALTER TABLE fortress_refresh_token
  ALTER COLUMN family_created_at SET NOT NULL;
ALTER TABLE fortress_refresh_token
  ALTER COLUMN family_created_at SET DEFAULT now();
ALTER TABLE fortress_refresh_token
  ADD COLUMN successor_token_hash VARCHAR(64);
ALTER TABLE fortress_refresh_token
  ADD COLUMN rotated_at TIMESTAMP;

CREATE TABLE fortress_auth_continuation (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  reason VARCHAR(32) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  consumed_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);
