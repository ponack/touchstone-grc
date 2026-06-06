-- 008_risks.sql
-- Phase 7 GRC surface: risk register.
--
-- Captures identified information-security risks the audited
-- boundary carries. Maps to:
--
--   SOC 2 CC3.1 — risk identification
--   SOC 2 CC3.2 — risk assessment + analysis
--   ISO 27001:2022 clause 6.1.2 — information security risk
--                                  assessment
--   ISO 27001:2022 A.5.7        — threat intelligence
--
-- A risk row carries the inherent and residual L×I rating
-- (likelihood × impact), the treatment strategy + plan, an owner
-- from the personnel register, and optional attachment to a single
-- asset or vendor row (the source of the risk).
--
-- The L and I scales reuse the existing four-tier vocab so the
-- whole GRC surface speaks the same language: low / medium / high /
-- critical. Score = L × I (1..16) is derived in the handler and
-- the UI rather than stored — keeps the schema and migration
-- straightforward; auditors can recompute from labels.
--
-- next_review_date drives auditor cadence just like the vendor
-- register: ?review_due=true surfaces rows where the field is null
-- or past today.

CREATE TYPE risk_category AS ENUM (
    'operational',
    'security',
    'privacy',
    'compliance',
    'financial',
    'reputational',
    'strategic',
    'third_party',
    'other'
);

CREATE TYPE risk_level AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE risk_treatment AS ENUM (
    'accept',
    'mitigate',
    'transfer',
    'avoid'
);

CREATE TYPE risk_status AS ENUM (
    'identified',
    'treating',
    'accepted',
    'closed'
);

CREATE TABLE risks (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                 UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title                  TEXT NOT NULL,
    description            TEXT,
    risk_category          risk_category NOT NULL DEFAULT 'security',
    inherent_likelihood    risk_level NOT NULL DEFAULT 'medium',
    inherent_impact        risk_level NOT NULL DEFAULT 'medium',
    residual_likelihood    risk_level NOT NULL DEFAULT 'medium',
    residual_impact        risk_level NOT NULL DEFAULT 'medium',
    treatment_strategy     risk_treatment NOT NULL DEFAULT 'mitigate',
    treatment_plan         TEXT,
    status                 risk_status NOT NULL DEFAULT 'identified',
    owner_id               UUID REFERENCES personnel(id) ON DELETE SET NULL,
    related_asset_id       UUID REFERENCES assets(id)   ON DELETE SET NULL,
    related_vendor_id      UUID REFERENCES vendors(id)  ON DELETE SET NULL,
    identified_date        DATE NOT NULL DEFAULT CURRENT_DATE,
    last_review_date       DATE,
    next_review_date       DATE,
    closed_date            DATE,
    tags                   TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    notes                  TEXT,
    created_by             UUID REFERENCES users(id),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, title),
    CHECK (status <> 'closed' OR closed_date IS NOT NULL)
);

CREATE INDEX idx_risks_org_status         ON risks(org_id, status);
CREATE INDEX idx_risks_org_category       ON risks(org_id, risk_category);
CREATE INDEX idx_risks_owner              ON risks(owner_id);
CREATE INDEX idx_risks_related_asset      ON risks(related_asset_id) WHERE related_asset_id IS NOT NULL;
CREATE INDEX idx_risks_related_vendor     ON risks(related_vendor_id) WHERE related_vendor_id IS NOT NULL;
CREATE INDEX idx_risks_org_next_review    ON risks(org_id, next_review_date) WHERE next_review_date IS NOT NULL;
