// Package updates owns the GitHub-release poller and the
// system_settings rows that back it. The poller is started by the
// API process at boot; the HTTP handler surfaces both the cached
// state and the cadence knob.
//
// Only platform admins (users.is_admin = true) can change the
// cadence or force a re-poll.
package updates

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Frequency is the operator-set check cadence. "off" disables the
// poller entirely; the cached fields stop updating.
type Frequency string

const (
	FrequencyOff     Frequency = "off"
	FrequencyDaily   Frequency = "daily"
	FrequencyWeekly  Frequency = "weekly"
	FrequencyMonthly Frequency = "monthly"
)

// Interval returns the wall-clock gap between polls for a given
// frequency, or 0 when the poller is off.
func (f Frequency) Interval() time.Duration {
	switch f {
	case FrequencyDaily:
		return 24 * time.Hour
	case FrequencyWeekly:
		return 7 * 24 * time.Hour
	case FrequencyMonthly:
		return 30 * 24 * time.Hour
	default:
		return 0
	}
}

// IsValid reports whether the value matches one of the four allowed
// frequencies. The DB CHECK constraint enforces this too; the Go
// validator is for fast HTTP rejection.
func (f Frequency) IsValid() bool {
	switch f {
	case FrequencyOff, FrequencyDaily, FrequencyWeekly, FrequencyMonthly:
		return true
	}
	return false
}

// Settings is the application-level view of the system_settings row.
// Pointer fields are nullable in the DB.
type Settings struct {
	Frequency                Frequency
	LatestReleaseTag         *string
	LatestReleaseURL         *string
	LatestReleasePublishedAt *time.Time
	LastCheckedAt            *time.Time
	UpdatedAt                time.Time
}

// Store reads and writes the single-row system_settings table.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Load returns the (always-present) single row. The 001 migration
// inserts the row at install time, so a missing row is a real error.
func (s *Store) Load(ctx context.Context) (Settings, error) {
	var out Settings
	row := s.pool.QueryRow(ctx, `
		SELECT update_check_frequency,
		       latest_release_tag,
		       latest_release_url,
		       latest_release_published_at,
		       last_checked_at,
		       updated_at
		  FROM system_settings
		 WHERE id = TRUE`)
	var freq string
	if err := row.Scan(
		&freq,
		&out.LatestReleaseTag,
		&out.LatestReleaseURL,
		&out.LatestReleasePublishedAt,
		&out.LastCheckedAt,
		&out.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Settings{}, errors.New("system_settings row missing — has migration 004 run?")
		}
		return Settings{}, fmt.Errorf("load system_settings: %w", err)
	}
	out.Frequency = Frequency(freq)
	return out, nil
}

// SetFrequency updates the cadence knob. The DB CHECK enforces the
// enum, so an invalid value returns a clean error rather than
// corrupting the row.
func (s *Store) SetFrequency(ctx context.Context, f Frequency) error {
	if !f.IsValid() {
		return fmt.Errorf("invalid frequency %q", f)
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE system_settings
		   SET update_check_frequency = $1,
		       updated_at             = now()
		 WHERE id = TRUE`, string(f))
	if err != nil {
		return fmt.Errorf("update frequency: %w", err)
	}
	return nil
}

// RecordCheck stores the polled GitHub-release metadata + the
// last_checked_at timestamp. Called by the poller after every
// successful fetch — including when no release exists (tag/url left
// nil) so we don't keep retrying a 404 repo.
func (s *Store) RecordCheck(ctx context.Context, tag, url string, publishedAt *time.Time, checkedAt time.Time) error {
	var tagArg, urlArg any
	if tag != "" {
		tagArg = tag
	}
	if url != "" {
		urlArg = url
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE system_settings
		   SET latest_release_tag          = $1,
		       latest_release_url          = $2,
		       latest_release_published_at = $3,
		       last_checked_at             = $4,
		       updated_at                  = now()
		 WHERE id = TRUE`, tagArg, urlArg, publishedAt, checkedAt)
	if err != nil {
		return fmt.Errorf("record check: %w", err)
	}
	return nil
}
