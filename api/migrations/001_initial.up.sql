-- 001_initial.sql
-- Foundation schema for Touchstone: multi-tenant orgs, users, API tokens,
-- and an append-only partitioned audit log.
--
-- Connectors, frameworks, controls, scans, evidence_items, exceptions,
-- personnel, assets, vendors, and risks all land in later migrations
-- (002+) so this file stays a true foundation that does not assume any
-- particular product feature.

-- ── Extensions ────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Users ─────────────────────────────────────────────────────────────────────

CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    avatar_url  TEXT,
    is_admin    BOOLEAN NOT NULL DEFAULT false,  -- platform super-admin (bootstrap)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Local-auth password hashes live in a side table so OIDC-only deployments
-- never touch a passwords table.
CREATE TABLE user_passwords (
    user_id        UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash  TEXT NOT NULL,                -- bcrypt
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Organizations (multi-tenant from day 1) ──────────────────────────────────

CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Roles include 'auditor' (read-only) as a first-class citizen — adding it
-- later is painful (Crucible learned this on v0.8.34). Auditor sees evidence,
-- scans, controls, and exports but cannot mutate anything.
CREATE TABLE organization_members (
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'member',
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id),
    CHECK (role IN ('admin', 'member', 'auditor'))
);

CREATE INDEX idx_org_members_user ON organization_members(user_id);

-- Org-scoped invitations (consumed at signup / acceptance).
CREATE TABLE organization_invites (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email        TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'member',
    token_hash   TEXT NOT NULL UNIQUE,           -- SHA-256 of the raw token
    invited_by   UUID REFERENCES users(id),
    expires_at   TIMESTAMPTZ NOT NULL,
    accepted_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (role IN ('admin', 'member', 'auditor'))
);

-- ── API Tokens ────────────────────────────────────────────────────────────────

CREATE TABLE api_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,            -- SHA-256 of the raw token
    last_used   TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);

-- ── Audit Log ─────────────────────────────────────────────────────────────────
-- Append-only, partitioned by month. The application layer runs a
-- StartPartitionMaintainer ticker that creates current + 2 months ahead
-- on startup and then monthly.

CREATE TABLE audit_events (
    id              BIGINT GENERATED ALWAYS AS IDENTITY,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id        UUID,
    actor_type      TEXT        NOT NULL DEFAULT 'user', -- user | system | scanner | api_token
    action          TEXT        NOT NULL,                -- e.g. scan.started, evidence.collected, exception.granted
    resource_id     TEXT,
    resource_type   TEXT,
    org_id          UUID REFERENCES organizations(id),
    ip_address      INET,
    context         JSONB       NOT NULL DEFAULT '{}',
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Initial partitions: current month (2026-05) + 2 ahead. The maintainer
-- keeps creating new partitions as time advances.
CREATE TABLE audit_events_2026_05 PARTITION OF audit_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_events_2026_06 PARTITION OF audit_events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE audit_events_2026_07 PARTITION OF audit_events
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');

CREATE INDEX idx_audit_org_time ON audit_events(org_id, occurred_at DESC);
CREATE INDEX idx_audit_actor   ON audit_events(actor_id, occurred_at DESC);
CREATE INDEX idx_audit_action  ON audit_events(action, occurred_at DESC);

-- DB-level immutability of audit records.
CREATE RULE audit_no_update AS ON UPDATE TO audit_events DO INSTEAD NOTHING;
CREATE RULE audit_no_delete AS ON DELETE TO audit_events DO INSTEAD NOTHING;
