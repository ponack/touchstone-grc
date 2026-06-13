ALTER TABLE trust_centers DROP COLUMN IF EXISTS show_incidents;
DROP TABLE IF EXISTS trust_incidents;
DROP TYPE  IF EXISTS incident_severity;
DROP TYPE  IF EXISTS incident_status;
