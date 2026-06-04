-- 006_assets.sql
-- Phase 7 GRC surface: asset inventory.
--
-- An asset is anything within the audited boundary that the
-- organization wants to track for compliance scope. The register
-- covers logical assets (applications, services, databases, code
-- repos, data stores, cloud accounts, infrastructure) and the
-- physical assets that occasionally sneak into scope on hybrid
-- estates (device).
--
-- Maps to ISO/IEC 27001:2022 A.5.9 (inventory of information and
-- other associated assets) + A.5.12 (information classification) +
-- SOC 2 CC6.1 (boundary). Auditors expect every asset to have a
-- named human owner; owner_id is the foundational link the
-- personnel register exists for.
--
-- classification is intentionally nullable — not every asset holds
-- data directly (e.g. a SaaS account that's just a tunnel), so the
-- field is optional. When present, it follows the canonical four-
-- tier public / internal / confidential / restricted ladder.
--
-- tags is a free-form TEXT[] for org-specific labels (e.g. "pci",
-- "ephi", "tier-1") so the auditor's grouping doesn't have to be
-- baked into the schema.

CREATE TYPE asset_type AS ENUM (
    'application',
    'service',
    'database',
    'repository',
    'data_store',
    'cloud_account',
    'infrastructure',
    'device',
    'other'
);

CREATE TYPE asset_classification AS ENUM (
    'public',
    'internal',
    'confidential',
    'restricted'
);

CREATE TYPE asset_environment AS ENUM (
    'production',
    'staging',
    'development',
    'other'
);

CREATE TYPE asset_criticality AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE asset_status AS ENUM (
    'active',
    'planned',
    'decommissioned'
);

CREATE TABLE assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    asset_type      asset_type NOT NULL,
    classification  asset_classification,
    environment     asset_environment NOT NULL DEFAULT 'production',
    criticality     asset_criticality NOT NULL DEFAULT 'medium',
    status          asset_status NOT NULL DEFAULT 'active',
    owner_id        UUID REFERENCES personnel(id) ON DELETE SET NULL,
    description     TEXT,
    external_ref    TEXT,
    tags            TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    notes           TEXT,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE INDEX idx_assets_org_type   ON assets(org_id, asset_type);
CREATE INDEX idx_assets_org_status ON assets(org_id, status);
CREATE INDEX idx_assets_owner      ON assets(owner_id);
