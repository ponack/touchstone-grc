-- 005_personnel.sql
-- Phase 7 GRC surface: personnel register.
--
-- Personnel are the workforce members whose access to in-scope
-- systems is governed by the audited control set. They are the
-- foundational register the other Phase 7 registers (assets,
-- vendors, risks) point at as the owner of a row. The personnel
-- record is intentionally narrow — name / role / department /
-- manager / employment dates / status — not a full HRIS sync. A
-- start-date / end-date pair is the auditor's primary input for
-- "who had access during the review window."
--
-- person_status drives termination evidence: 'terminated' rows with
-- end_date set are the rows access reviews must verify have lost
-- access to in-scope systems. The HIPAA 164.308(a)(3)(ii)(C)
-- termination evidence chain (stale IAM keys) can later cross-
-- check against this list.
--
-- email is UNIQUE per-org so the same human can plausibly appear
-- in multiple orgs (the operator's own staff vs a customer org)
-- without colliding.

CREATE TYPE person_status AS ENUM (
    'active',
    'on_leave',
    'terminated'
);

CREATE TABLE personnel (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    full_name       TEXT NOT NULL,
    email           TEXT NOT NULL,
    role            TEXT NOT NULL,
    department      TEXT,
    manager_id      UUID REFERENCES personnel(id) ON DELETE SET NULL,
    start_date      DATE NOT NULL,
    end_date        DATE,
    status          person_status NOT NULL DEFAULT 'active',
    notes           TEXT,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, email),
    CHECK (end_date IS NULL OR end_date >= start_date),
    CHECK (status <> 'terminated' OR end_date IS NOT NULL)
);

CREATE INDEX idx_personnel_org_status ON personnel(org_id, status);
CREATE INDEX idx_personnel_manager    ON personnel(manager_id);
