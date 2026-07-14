-- This sentinel is created only by the Fortress migration engine after its
-- Unicode-aware data step. Applying this SQL directly fails closed.
INSERT INTO fortress_email_migration_ready (id) VALUES (1);
CREATE UNIQUE INDEX user_email_ci_unique ON fortress_user (email COLLATE NOCASE);
CREATE UNIQUE INDEX login_identifier_email_ci_unique
  ON fortress_login_identifier (value COLLATE NOCASE)
  WHERE type = 'email';
DROP TABLE fortress_email_migration_ready;
