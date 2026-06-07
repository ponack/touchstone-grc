DROP INDEX IF EXISTS idx_vendors_trust_public;
ALTER TABLE vendors DROP COLUMN IF EXISTS trust_center_public;
DROP TABLE IF EXISTS trust_centers;
