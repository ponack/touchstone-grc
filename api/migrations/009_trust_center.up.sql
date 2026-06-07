-- 009_trust_center.sql
-- Phase 8: Trust Center MVP.
--
-- A trust center is the public-facing security-posture page
-- prospective customers visit during evaluation. The page is
-- served unauthenticated at /trust/{slug} once is_public flips on.
--
-- One row per org (FK is the PK). slug is globally unique across
-- the multi-tenant install — public URLs cannot collide between
-- two tenants. Defaults are deliberately empty / off; the row is
-- auto-created on first GET by the handler so the admin form has
-- something to edit without an explicit "create" step.
--
-- Branding fields are intentionally minimal for the MVP:
--   display_name        — override organizations.name on the page
--   tagline             — single-line elevator pitch under the title
--   primary_color       — hex string the page uses for accent
--                          (matches the Forge variable shape)
--   logo_url            — optional brand logo
--   contact_email       — published mailto: target
--   contact_url         — published "request our questionnaire" link
--
-- Section visibility toggles let the admin hide pieces without
-- destroying the underlying data (e.g. hide subprocessors during
-- a renegotiation).
--
-- The slug CHECK enforces lowercase kebab-case so the URL space
-- stays predictable across tenants.
--
-- Companion: vendors gains a trust_center_public boolean — the
-- per-row toggle that decides whether a vendor appears in the
-- subprocessor section.

CREATE TABLE trust_centers (
    org_id              UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    slug                TEXT NOT NULL UNIQUE,
    is_public           BOOLEAN NOT NULL DEFAULT false,
    display_name        TEXT,
    tagline             TEXT,
    primary_color       TEXT,
    logo_url            TEXT,
    contact_email       TEXT,
    contact_url         TEXT,
    show_frameworks     BOOLEAN NOT NULL DEFAULT true,
    show_subprocessors  BOOLEAN NOT NULL DEFAULT true,
    show_contact        BOOLEAN NOT NULL DEFAULT true,
    created_by          UUID REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$')
);

CREATE INDEX idx_trust_centers_public ON trust_centers(slug) WHERE is_public = true;

ALTER TABLE vendors ADD COLUMN trust_center_public BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX idx_vendors_trust_public ON vendors(org_id) WHERE trust_center_public = true;
