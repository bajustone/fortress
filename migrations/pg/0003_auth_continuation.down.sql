-- Fortress migration 0003 rollback: auth continuation + refresh-session metadata (PostgreSQL)

DROP TABLE IF EXISTS fortress_auth_continuation CASCADE;
ALTER TABLE fortress_refresh_token DROP COLUMN rotated_at;
ALTER TABLE fortress_refresh_token DROP COLUMN successor_token_hash;
ALTER TABLE fortress_refresh_token DROP COLUMN family_created_at;
