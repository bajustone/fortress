-- Fortress migration 0008: bounded MFA continuation attempts.
ALTER TABLE fortress_auth_continuation ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fortress_auth_continuation ADD COLUMN last_failed_at INTEGER;
ALTER TABLE fortress_auth_continuation ADD COLUMN invalidated_at INTEGER;
ALTER TABLE fortress_auth_continuation ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 5;
ALTER TABLE fortress_auth_continuation ADD COLUMN cooldown_seconds INTEGER NOT NULL DEFAULT 1;
CREATE INDEX auth_continuation_failure_idx ON fortress_auth_continuation (user_id, reason, last_failed_at);
