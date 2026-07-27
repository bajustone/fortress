-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.
-- dialect: pg
-- version: 0009
-- name: encrypt_totp_secrets
-- direction: up

DELETE FROM fortress_backup_code;
DELETE FROM fortress_trusted_device;
DELETE FROM fortress_two_factor_secret;
