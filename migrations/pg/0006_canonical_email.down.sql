-- Canonicalization and duplicate-account quarantine are intentionally irreversible.
DROP INDEX IF EXISTS login_identifier_email_ci_unique;
DROP INDEX IF EXISTS user_email_ci_unique;
