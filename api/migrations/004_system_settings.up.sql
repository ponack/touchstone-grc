-- system_settings is a single-row key-value table for instance-wide
-- configuration. v0.5.1 introduces it to hold the GitHub-release
-- update-check cadence and the cached latest-release metadata.
-- Future system settings (default retention, default scan cadence,
-- etc.) extend this table rather than spawning new ones.
--
-- The single-row invariant is enforced with id boolean PRIMARY KEY
-- CHECK (id = TRUE) — a pattern that's noisier than EXISTS-based
-- alternatives but lets ON CONFLICT (id) DO UPDATE work cleanly.
CREATE TABLE system_settings (
    id                          BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id = TRUE),
    update_check_frequency      TEXT    NOT NULL DEFAULT 'weekly'
                                CHECK (update_check_frequency IN ('off', 'daily', 'weekly', 'monthly')),
    latest_release_tag          TEXT,
    latest_release_url          TEXT,
    latest_release_published_at TIMESTAMPTZ,
    last_checked_at             TIMESTAMPTZ,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO system_settings (id) VALUES (TRUE);
