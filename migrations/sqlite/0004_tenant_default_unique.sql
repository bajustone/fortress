UPDATE fortress_tenant_user
SET is_default = 0
WHERE is_default = 1
  AND rowid NOT IN (
    SELECT MIN(rowid)
    FROM fortress_tenant_user
    WHERE is_default = 1
    GROUP BY user_id
  );

CREATE UNIQUE INDEX IF NOT EXISTS fortress_tenant_user_one_default_idx
  ON fortress_tenant_user (user_id)
  WHERE is_default = 1;
