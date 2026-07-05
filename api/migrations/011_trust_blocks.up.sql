-- 011_trust_blocks.sql
-- Phase 8 continuation: custom Markdown blocks for the Trust Center.
--
-- Named, ordered content sections the admin can drop onto the
-- public trust page: "Data handling", "SLA / uptime", "Incident
-- policy", "Sub-processor addendum", and so on. Escape hatch for
-- org-specific copy that doesn't fit the fixed framework /
-- subprocessor / incident sections.
--
-- Each row carries its own is_public flag so an admin can draft
-- privately and publish later. The section-level visibility toggle
-- lives on trust_centers.show_blocks (mirrors the show_frameworks /
-- show_subprocessors / show_incidents / show_contact flags).
--
-- position is the sort key. The UI provides move-up / move-down
-- buttons that swap positions with the immediate neighbor; there's
-- no CHECK enforcing uniqueness because the admin flow tolerates
-- ties briefly during a swap.
--
-- Maps loosely to SOC 2 CC2.3 (external communications) +
-- ISO/IEC 27001:2022 A.5.18 (public information).

CREATE TABLE trust_blocks (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    heading       TEXT NOT NULL,
    body_markdown TEXT NOT NULL,
    position      INT  NOT NULL DEFAULT 0,
    is_public     BOOLEAN NOT NULL DEFAULT false,
    created_by    UUID REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_trust_blocks_org_position ON trust_blocks(org_id, position);
CREATE INDEX idx_trust_blocks_public       ON trust_blocks(org_id, position) WHERE is_public = true;

ALTER TABLE trust_centers ADD COLUMN show_blocks BOOLEAN NOT NULL DEFAULT false;
