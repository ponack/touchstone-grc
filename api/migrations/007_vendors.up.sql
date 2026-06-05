-- 007_vendors.sql
-- Phase 7 GRC surface: vendor / supplier register.
--
-- Captures third-party suppliers whose services or technology fall
-- inside the audited boundary. Maps to:
--
--   SOC 2 CC9.2          — third-party risk
--   PCI DSS 12.8         — service provider relationships
--   ISO 27001:2022 A.5.19 — information security in supplier
--                            relationships
--                A.5.20 — addressing IS within supplier agreements
--                A.5.21 — managing IS in the ICT supply chain
--                A.5.22 — monitoring, review, change management of
--                            supplier services
--
-- vendor_type distinguishes service tiers that drive different
-- review depth (a `processor` handling PII gets a tighter cadence
-- than a `hardware` supplier of office laptops). The four-tier
-- criticality is the operational-dependency rating, separate from
-- asset_criticality (which rates how critical a single asset is).
--
-- data_classification reuses the asset_classification enum so the
-- vocabulary stays consistent across the audited boundary.
--
-- The triple of (onboarded_date, offboarded_date, status) plays the
-- same role personnel.start_date / end_date / status plays for
-- people: a vendor "had access to in-scope data between X and Y".
-- Two CHECKs keep the dates and status coherent.

CREATE TYPE vendor_type AS ENUM (
    'saas',
    'paas',
    'iaas',
    'processor',
    'subprocessor',
    'hardware',
    'professional_services',
    'other'
);

CREATE TYPE vendor_criticality AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE vendor_status AS ENUM (
    'prospective',
    'active',
    'terminated'
);

CREATE TABLE vendors (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    vendor_type           vendor_type NOT NULL,
    criticality           vendor_criticality NOT NULL DEFAULT 'medium',
    status                vendor_status NOT NULL DEFAULT 'active',
    data_classification   asset_classification,
    owner_id              UUID REFERENCES personnel(id) ON DELETE SET NULL,
    website               TEXT,
    contact_name          TEXT,
    contact_email         TEXT,
    description           TEXT,
    onboarded_date        DATE,
    offboarded_date       DATE,
    assurance_report      TEXT,
    last_review_date      DATE,
    next_review_date      DATE,
    tags                  TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    notes                 TEXT,
    created_by            UUID REFERENCES users(id),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name),
    CHECK (offboarded_date IS NULL OR onboarded_date IS NULL OR offboarded_date >= onboarded_date),
    CHECK (status <> 'terminated' OR offboarded_date IS NOT NULL)
);

CREATE INDEX idx_vendors_org_status      ON vendors(org_id, status);
CREATE INDEX idx_vendors_org_criticality ON vendors(org_id, criticality);
CREATE INDEX idx_vendors_owner           ON vendors(owner_id);
CREATE INDEX idx_vendors_org_next_review ON vendors(org_id, next_review_date) WHERE next_review_date IS NOT NULL;
