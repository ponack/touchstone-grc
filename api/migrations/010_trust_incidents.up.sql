-- 010_trust_incidents.sql
-- Phase 8 continuation: incident history for the Trust Center.
--
-- A trust incident is a recorded security / availability event the
-- org may want to surface on the public trust page. Maps to:
--
--   SOC 2 CC7.4               — incident response procedures
--   SOC 2 CC2.3               — external communication during incidents
--   ISO 27001:2022 A.5.24-26  — IS incident management / planning,
--                                  preparation, response, learning
--
-- One row per recorded incident. Two visibility tiers:
--
--   summary           — internal text the org keeps for the audit
--                       trail (root cause, blameless review notes).
--   public_response   — the cleaned-up version that appears on the
--                       public trust page when is_public=true.
--
-- The CHECK keeps state consistent: 'resolved' status requires a
-- resolved_at timestamp so the closure point is unambiguous in the
-- audit trail.
--
-- Companion: trust_centers gains show_incidents — the section
-- visibility toggle that mirrors the existing show_frameworks /
-- show_subprocessors / show_contact flags.

CREATE TYPE incident_status AS ENUM (
    'ongoing',
    'monitoring',
    'resolved'
);

CREATE TYPE incident_severity AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TABLE trust_incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    status          incident_status NOT NULL DEFAULT 'ongoing',
    severity        incident_severity NOT NULL DEFAULT 'medium',
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    summary         TEXT,
    public_response TEXT,
    is_public       BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (status <> 'resolved' OR resolved_at IS NOT NULL)
);

CREATE INDEX idx_trust_incidents_org_status ON trust_incidents(org_id, status);
CREATE INDEX idx_trust_incidents_public ON trust_incidents(org_id, occurred_at DESC)
    WHERE is_public = true;

ALTER TABLE trust_centers ADD COLUMN show_incidents BOOLEAN NOT NULL DEFAULT false;
