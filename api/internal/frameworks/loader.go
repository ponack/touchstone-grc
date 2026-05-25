package frameworks

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ponack/touchstone/internal/frameworks/packs"
)

// Load reads every YAML manifest from the embedded packs FS, parses
// each, and upserts the framework + controls into the database. Idempotent:
// repeated calls (e.g. on every server restart) update text fields but
// preserve existing IDs so evidence_items references remain valid.
func Load(ctx context.Context, pool *pgxpool.Pool) error {
	entries, err := packs.FS.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read packs FS: %w", err)
	}

	var loaded, controls int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := packs.FS.ReadFile(e.Name())
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Name(), err)
		}
		p, err := ParsePack(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		if err := upsertPack(ctx, pool, p); err != nil {
			return fmt.Errorf("upsert %s: %w", p.Code, err)
		}
		loaded++
		controls += len(p.Controls)
	}

	slog.Info("control packs loaded", "frameworks", loaded, "controls", controls)
	return nil
}

func upsertPack(ctx context.Context, pool *pgxpool.Pool, p *Pack) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var fwID string
	err = tx.QueryRow(ctx, `
		INSERT INTO frameworks (code, name, version)
		VALUES ($1, $2, NULLIF($3, ''))
		ON CONFLICT (code) DO UPDATE
		SET name = EXCLUDED.name, version = EXCLUDED.version
		RETURNING id
	`, p.Code, p.Name, p.Version).Scan(&fwID)
	if err != nil {
		return err
	}

	for _, c := range p.Controls {
		_, err = tx.Exec(ctx, `
			INSERT INTO controls (framework_id, code, title, description, severity, policy_path)
			VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6)
			ON CONFLICT (framework_id, code) DO UPDATE
			SET title       = EXCLUDED.title,
			    description = EXCLUDED.description,
			    severity    = EXCLUDED.severity,
			    policy_path = EXCLUDED.policy_path
		`, fwID, c.Code, c.Title, c.Description, c.Severity, c.PolicyPath)
		if err != nil {
			return fmt.Errorf("control %s: %w", c.Code, err)
		}
	}

	return tx.Commit(ctx)
}
