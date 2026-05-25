DROP TABLE IF EXISTS river_client_queue;
DROP TABLE IF EXISTS river_queue;
DROP TABLE IF EXISTS river_leader;
DROP TABLE IF EXISTS river_job;
DROP FUNCTION IF EXISTS river_job_state_in_bitmask(BIT(8), river_job_state);
DROP TABLE IF EXISTS river_migration;
DROP TYPE  IF EXISTS river_job_state;
