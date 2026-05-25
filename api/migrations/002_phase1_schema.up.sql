-- 002_phase1_schema.sql
-- Phase 1 schema: connectors, frameworks, controls, scans, evidence,
-- exceptions. Foundation tables only — no Go code touches them yet.
-- Application packages land in follow-up PRs.

-- ── Connectors ────────────────────────────────────────────────────────────────
-- A configured integration (e.g. one AWS account, one GitHub org). The
-- connector kind selects which scanner implementation runs; config holds
-- non-sensitive parameters (account_id, regions, etc.). Credentials live
-- in secrets_ref as a pointer into the application-level secret store
-- so they never sit in plaintext in this row.

CREATE TABLE connectors (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,                       -- aws | github | okta | google_workspace | m365 | ...
    name          TEXT NOT NULL,
    config        JSONB NOT NULL DEFAULT '{}',
    secrets_ref   TEXT,                                -- pointer into secret store; never the raw secret
    schedule_cron TEXT,                                -- nullable = on-demand only
    is_disabled   BOOLEAN NOT NULL DEFAULT false,
    last_scan_at  TIMESTAMPTZ,
    created_by    UUID REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE INDEX idx_connectors_org  ON connectors(org_id);
CREATE INDEX idx_connectors_kind ON connectors(kind);

-- ── Frameworks + Controls ────────────────────────────────────────────────────
-- Frameworks are global (one row per shipped control pack). Each ships
-- with its set of controls. Orgs opt in via org_frameworks.

CREATE TABLE frameworks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        TEXT NOT NULL UNIQUE,                  -- soc2_2017 | cis_aws_v3 | hipaa | pci_dss_v4 | iso_27001_2022 | nist_csf
    name        TEXT NOT NULL,
    version     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE controls (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id  UUID NOT NULL REFERENCES frameworks(id) ON DELETE CASCADE,
    code          TEXT NOT NULL,                       -- e.g. "CC6.1", "CIS-1.4"
    title         TEXT NOT NULL,
    description   TEXT,
    severity      TEXT NOT NULL DEFAULT 'medium',
    policy_path   TEXT NOT NULL,                       -- e.g. "soc2/cc6_1.rego"
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (framework_id, code),
    CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

CREATE INDEX idx_controls_framework ON controls(framework_id);

CREATE TABLE org_frameworks (
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    framework_id UUID NOT NULL REFERENCES frameworks(id)    ON DELETE CASCADE,
    enabled_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    enabled_by   UUID REFERENCES users(id),
    PRIMARY KEY (org_id, framework_id)
);

-- ── Scans ─────────────────────────────────────────────────────────────────────
-- One execution of a connector against an org. Status transitions follow
-- queued → running → (succeeded|failed|canceled). Evidence items are
-- populated as the scan runs.

CREATE TYPE scan_status AS ENUM (
    'queued',
    'running',
    'succeeded',
    'failed',
    'canceled'
);

CREATE TYPE scan_trigger AS ENUM (
    'scheduled',
    'manual',
    'api'
);

CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    connector_id    UUID NOT NULL REFERENCES connectors(id)    ON DELETE CASCADE,
    status          scan_status  NOT NULL DEFAULT 'queued',
    trigger         scan_trigger NOT NULL DEFAULT 'manual',
    triggered_by    UUID REFERENCES users(id),
    artifact_key    TEXT,                                -- MinIO key for raw scan artifact
    error_message   TEXT,
    resources_count INT NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scans_org_time   ON scans(org_id, created_at DESC);
CREATE INDEX idx_scans_connector  ON scans(connector_id, created_at DESC);
CREATE INDEX idx_scans_status     ON scans(status);

-- ── Evidence Items ───────────────────────────────────────────────────────────
-- One row per (scan, control) result. `details` carries the OPA decision
-- payload (passed/failed resources, messages). `artifact_key` is an
-- optional MinIO pointer for evidence too large to inline.
--
-- control_id uses ON DELETE RESTRICT — controls should not be deleted
-- while evidence references them, to keep the audit trail intact.

CREATE TYPE evidence_status AS ENUM (
    'pass',
    'fail',
    'partial',
    'not_applicable',
    'error'
);

CREATE TABLE evidence_items (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_id       UUID NOT NULL REFERENCES scans(id)         ON DELETE CASCADE,
    control_id    UUID NOT NULL REFERENCES controls(id)      ON DELETE RESTRICT,
    status        evidence_status NOT NULL,
    details       JSONB NOT NULL DEFAULT '{}',
    artifact_key  TEXT,
    collected_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_evidence_scan       ON evidence_items(scan_id);
CREATE INDEX idx_evidence_control    ON evidence_items(control_id);
CREATE INDEX idx_evidence_org_status ON evidence_items(org_id, status);

-- ── Exceptions ───────────────────────────────────────────────────────────────
-- Acknowledged gaps. Suppress a fail without erasing it from the audit
-- trail. Optional resource_key narrows the scope to a single resource;
-- NULL means the exception applies to every failure of this control in
-- this org. Exceptions can expire (expires_at) or be explicitly revoked
-- (revoked_at / revoked_by). The partial index keeps lookups for active
-- exceptions cheap.

CREATE TABLE exceptions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    control_id    UUID NOT NULL REFERENCES controls(id)      ON DELETE CASCADE,
    resource_key  TEXT,
    reason        TEXT NOT NULL,
    granted_by    UUID NOT NULL REFERENCES users(id),
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    revoked_by    UUID REFERENCES users(id)
);

CREATE INDEX idx_exceptions_org_control ON exceptions(org_id, control_id);
CREATE INDEX idx_exceptions_active      ON exceptions(org_id) WHERE revoked_at IS NULL;
