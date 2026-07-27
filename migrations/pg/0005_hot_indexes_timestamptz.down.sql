-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: pg
-- version: 0005
-- name: hot_indexes_timestamptz
-- direction: down

ALTER TABLE fortress_schema_version ALTER COLUMN applied_at TYPE TIMESTAMP USING applied_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user ALTER COLUMN updated_at TYPE TIMESTAMP USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN family_created_at TYPE TIMESTAMP USING family_created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN rotated_at TYPE TIMESTAMP USING rotated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN last_active_at TYPE TIMESTAMP USING last_active_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN consumed_at TYPE TIMESTAMP USING consumed_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_service_account ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_service_account ALTER COLUMN updated_at TYPE TIMESTAMP USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN used_at TYPE TIMESTAMP USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN used_at TYPE TIMESTAMP USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN last_used_at TYPE TIMESTAMP USING last_used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_two_factor_secret ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_backup_code ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN last_used_at TYPE TIMESTAMP USING last_used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN token_expires_at TYPE TIMESTAMP USING token_expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN updated_at TYPE TIMESTAMP USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_tenant ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_tenant ALTER COLUMN updated_at TYPE TIMESTAMP USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_client ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN used_at TYPE TIMESTAMP USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_access_token ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_access_token ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN issued_at TYPE TIMESTAMP USING issued_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN used_at TYPE TIMESTAMP USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN used_at TYPE TIMESTAMP USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_signing_key ALTER COLUMN rotated_at TYPE TIMESTAMP USING rotated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_signing_key ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user_scope_assignment ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN last_failed_at TYPE TIMESTAMP USING last_failed_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN locked_until TYPE TIMESTAMP USING locked_until AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_audit_log ALTER COLUMN timestamp TYPE TIMESTAMP USING timestamp AT TIME ZONE 'UTC';
ALTER TABLE fortress_audit_log ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_endpoint ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN last_attempt_at TYPE TIMESTAMP USING last_attempt_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN next_retry_at TYPE TIMESTAMP USING next_retry_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_credential ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_challenge ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_challenge ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';

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
