-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: sqlite
-- version: 0005
-- name: hot_indexes_timestamptz
-- direction: down

DROP INDEX IF EXISTS audit_log_timestamp_idx;
DROP INDEX IF EXISTS webhook_delivery_retry_idx;
DROP INDEX IF EXISTS trusted_device_user_idx;
DROP INDEX IF EXISTS backup_code_user_idx;
DROP INDEX IF EXISTS direct_permission_binding_subject_idx;
DROP INDEX IF EXISTS role_binding_subject_idx;
DROP INDEX IF EXISTS magic_link_token_token_idx;
DROP INDEX IF EXISTS email_verification_token_token_idx;
DROP INDEX IF EXISTS refresh_token_user_idx;
DROP INDEX IF EXISTS refresh_token_family_idx;
