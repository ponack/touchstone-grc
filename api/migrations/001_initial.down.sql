DROP RULE IF EXISTS audit_no_delete ON audit_events;
DROP RULE IF EXISTS audit_no_update ON audit_events;

DROP TABLE IF EXISTS audit_events_2026_07;
DROP TABLE IF EXISTS audit_events_2026_06;
DROP TABLE IF EXISTS audit_events_2026_05;
DROP TABLE IF EXISTS audit_events;

DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS organization_invites;
DROP TABLE IF EXISTS organization_members;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS user_passwords;
DROP TABLE IF EXISTS users;
