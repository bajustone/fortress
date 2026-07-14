WITH ranked_defaults AS (
  SELECT ctid, ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY tenant_id) AS position
  FROM fortress_tenant_user
  WHERE is_default = true
)
UPDATE fortress_tenant_user AS membership
SET is_default = false
FROM ranked_defaults
WHERE membership.ctid = ranked_defaults.ctid
  AND ranked_defaults.position > 1;

CREATE UNIQUE INDEX IF NOT EXISTS fortress_tenant_user_one_default_idx
  ON fortress_tenant_user (user_id)
  WHERE is_default = true;
