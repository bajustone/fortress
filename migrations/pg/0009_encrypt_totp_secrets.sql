-- Existing TOTP seeds were stored in plaintext. SQL migrations cannot encrypt
-- them with the application-held key, so fail securely by requiring re-enrolment.
DELETE FROM fortress_backup_code;
DELETE FROM fortress_trusted_device;
DELETE FROM fortress_two_factor_secret;
