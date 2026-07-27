-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: pg
-- version: 0002
-- name: initial_schema
-- direction: down

DROP TABLE IF EXISTS fortress_webauthn_challenge CASCADE;
DROP TABLE IF EXISTS fortress_webauthn_credential CASCADE;
DROP TABLE IF EXISTS fortress_webhook_delivery CASCADE;
DROP TABLE IF EXISTS fortress_webhook_endpoint CASCADE;
DROP TABLE IF EXISTS fortress_audit_log CASCADE;
DROP TABLE IF EXISTS fortress_account_lockout CASCADE;
DROP TABLE IF EXISTS fortress_user_scope_assignment CASCADE;
DROP TABLE IF EXISTS fortress_oauth_signing_key CASCADE;
DROP TABLE IF EXISTS fortress_oauth_pending_flow CASCADE;
DROP TABLE IF EXISTS fortress_oauth_refresh_token CASCADE;
DROP TABLE IF EXISTS fortress_oauth_access_token CASCADE;
DROP TABLE IF EXISTS fortress_oauth_authorization_code CASCADE;
DROP TABLE IF EXISTS fortress_oauth_client CASCADE;
DROP TABLE IF EXISTS fortress_tenant_user CASCADE;
DROP TABLE IF EXISTS fortress_tenant CASCADE;
DROP TABLE IF EXISTS fortress_social_account CASCADE;
DROP TABLE IF EXISTS fortress_trusted_device CASCADE;
DROP TABLE IF EXISTS fortress_backup_code CASCADE;
DROP TABLE IF EXISTS fortress_two_factor_secret CASCADE;
DROP TABLE IF EXISTS fortress_api_key CASCADE;
DROP TABLE IF EXISTS fortress_magic_link_token CASCADE;
DROP TABLE IF EXISTS fortress_email_verification_token CASCADE;
DROP TABLE IF EXISTS fortress_direct_permission_binding CASCADE;
DROP TABLE IF EXISTS fortress_role_binding CASCADE;
DROP TABLE IF EXISTS fortress_role_permission CASCADE;
DROP TABLE IF EXISTS fortress_role CASCADE;
DROP TABLE IF EXISTS fortress_permission CASCADE;
DROP TABLE IF EXISTS fortress_resource CASCADE;
DROP TABLE IF EXISTS fortress_service_account CASCADE;
DROP TABLE IF EXISTS fortress_group_user CASCADE;
DROP TABLE IF EXISTS fortress_group CASCADE;
DROP TABLE IF EXISTS fortress_refresh_token CASCADE;
DROP TABLE IF EXISTS fortress_login_identifier CASCADE;
DROP TABLE IF EXISTS fortress_user CASCADE;
