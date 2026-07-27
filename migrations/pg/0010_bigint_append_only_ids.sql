-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: pg
-- version: 0010
-- name: bigint_append_only_ids
-- direction: up

ALTER SEQUENCE fortress_refresh_token_id_seq AS BIGINT;
ALTER TABLE fortress_refresh_token ALTER COLUMN id TYPE BIGINT;
ALTER SEQUENCE fortress_auth_continuation_id_seq AS BIGINT;
ALTER TABLE fortress_auth_continuation ALTER COLUMN id TYPE BIGINT;
ALTER SEQUENCE fortress_email_verification_token_id_seq AS BIGINT;
ALTER TABLE fortress_email_verification_token ALTER COLUMN id TYPE BIGINT;
ALTER SEQUENCE fortress_magic_link_token_id_seq AS BIGINT;
ALTER TABLE fortress_magic_link_token ALTER COLUMN id TYPE BIGINT;
ALTER SEQUENCE fortress_oauth_authorization_code_id_seq AS BIGINT;
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN id TYPE BIGINT;
ALTER SEQUENCE fortress_oauth_access_token_id_seq AS BIGINT;
ALTER TABLE fortress_oauth_access_token ALTER COLUMN id TYPE BIGINT;
ALTER SEQUENCE fortress_oauth_refresh_token_id_seq AS BIGINT;
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN id TYPE BIGINT;
ALTER SEQUENCE fortress_oauth_pending_flow_id_seq AS BIGINT;
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN id TYPE BIGINT;
ALTER SEQUENCE fortress_audit_log_id_seq AS BIGINT;
ALTER TABLE fortress_audit_log ALTER COLUMN id TYPE BIGINT;
ALTER SEQUENCE fortress_webhook_delivery_id_seq AS BIGINT;
ALTER TABLE fortress_webhook_delivery ALTER COLUMN id TYPE BIGINT;
ALTER SEQUENCE fortress_webauthn_challenge_id_seq AS BIGINT;
ALTER TABLE fortress_webauthn_challenge ALTER COLUMN id TYPE BIGINT;
