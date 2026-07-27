-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: pg
-- version: 0005
-- name: hot_indexes_timestamptz
-- direction: up

CREATE INDEX refresh_token_family_idx ON fortress_refresh_token (token_family);
CREATE INDEX refresh_token_user_idx ON fortress_refresh_token (user_id);
CREATE INDEX email_verification_token_token_idx ON fortress_email_verification_token (token);
CREATE INDEX magic_link_token_token_idx ON fortress_magic_link_token (token);
CREATE INDEX role_binding_subject_idx ON fortress_role_binding (subject_type, subject_id);
CREATE INDEX direct_permission_binding_subject_idx ON fortress_direct_permission_binding (subject_type, subject_id);
CREATE INDEX backup_code_user_idx ON fortress_backup_code (user_id);
CREATE INDEX trusted_device_user_idx ON fortress_trusted_device (user_id);
CREATE INDEX webhook_delivery_retry_idx ON fortress_webhook_delivery (status, next_retry_at);
CREATE INDEX audit_log_timestamp_idx ON fortress_audit_log (timestamp);

ALTER TABLE fortress_schema_version ALTER COLUMN applied_at TYPE TIMESTAMPTZ USING applied_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN family_created_at TYPE TIMESTAMPTZ USING family_created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN rotated_at TYPE TIMESTAMPTZ USING rotated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN last_active_at TYPE TIMESTAMPTZ USING last_active_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN consumed_at TYPE TIMESTAMPTZ USING consumed_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_service_account ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_service_account ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN last_used_at TYPE TIMESTAMPTZ USING last_used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_two_factor_secret ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_backup_code ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN last_used_at TYPE TIMESTAMPTZ USING last_used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN token_expires_at TYPE TIMESTAMPTZ USING token_expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_tenant ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_tenant ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_client ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_access_token ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_access_token ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN issued_at TYPE TIMESTAMPTZ USING issued_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_signing_key ALTER COLUMN rotated_at TYPE TIMESTAMPTZ USING rotated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_signing_key ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user_scope_assignment ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN last_failed_at TYPE TIMESTAMPTZ USING last_failed_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN locked_until TYPE TIMESTAMPTZ USING locked_until AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_audit_log ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp AT TIME ZONE 'UTC';
ALTER TABLE fortress_audit_log ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_endpoint ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN last_attempt_at TYPE TIMESTAMPTZ USING last_attempt_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN next_retry_at TYPE TIMESTAMPTZ USING next_retry_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_credential ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_challenge ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_challenge ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
