// Package exports renders evidence in auditor-friendly formats.
// PR F starts with the single-scan CSV — the universally accepted
// artifact for "what was true at this point in time". PDF reports and
// org-wide latest-per-control CSVs land in follow-up PRs.
package exports

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	"github.com/ponack/touchstone/internal/auth"
)

type Handler struct {
	pool *pgxpool.Pool
}

func NewHandler(pool *pgxpool.Pool) *Handler {
	return &Handler{pool: pool}
}

// Register wires GET /api/v1/scans/:id/export.csv. Mounted under the
// existing protected v1 group so auth + org-scoping apply.
func (h *Handler) Register(g *echo.Group) {
	g.GET("/scans/:id/export.csv", h.ScanCSV)
}

type evidenceRow struct {
	framework     string
	controlCode   string
	controlTitle  string
	severity      string
	status        string
	message       string
	failuresCount int
	collectedAt   time.Time
}

func (h *Handler) ScanCSV(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	scanID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	// Confirm the scan belongs to this org. Avoids leaking even the
	// existence of a foreign scan via the export URL.
	var exists bool
	if err := h.pool.QueryRow(c.Request().Context(),
		`SELECT EXISTS (SELECT 1 FROM scans WHERE id = $1 AND org_id = $2)`,
		scanID, orgID,
	).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return echo.NewHTTPError(http.StatusNotFound, "scan not found")
	}

	rows, err := h.loadRows(c.Request().Context(), orgID, scanID)
	if err != nil {
		return err
	}

	res := c.Response()
	res.Header().Set("Content-Type", "text/csv; charset=utf-8")
	res.Header().Set(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="touchstone-scan-%s.csv"`, scanID.String()),
	)
	res.WriteHeader(http.StatusOK)

	w := csv.NewWriter(res.Writer)
	defer w.Flush()

	if err := w.Write([]string{
		"framework_code",
		"control_code",
		"control_title",
		"severity",
		"status",
		"message",
		"failures_count",
		"collected_at",
	}); err != nil {
		return err
	}
	for _, r := range rows {
		if err := w.Write([]string{
			r.framework,
			r.controlCode,
			r.controlTitle,
			r.severity,
			r.status,
			r.message,
			fmt.Sprintf("%d", r.failuresCount),
			r.collectedAt.UTC().Format(time.RFC3339),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) loadRows(ctx context.Context, orgID, scanID uuid.UUID) ([]evidenceRow, error) {
	q, err := h.pool.Query(ctx, `
		SELECT f.code, c.code, c.title, c.severity, e.status, e.details, e.collected_at
		FROM evidence_items e
		JOIN controls c   ON c.id = e.control_id
		JOIN frameworks f ON f.id = c.framework_id
		WHERE e.org_id = $1 AND e.scan_id = $2
		ORDER BY f.code, c.code
	`, orgID, scanID)
	if err != nil {
		return nil, err
	}
	defer q.Close()

	out := []evidenceRow{}
	for q.Next() {
		var r evidenceRow
		var details []byte
		if err := q.Scan(&r.framework, &r.controlCode, &r.controlTitle, &r.severity, &r.status, &details, &r.collectedAt); err != nil {
			return nil, err
		}
		r.message, r.failuresCount = parseDetails(details)
		out = append(out, r)
	}
	if err := q.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseDetails extracts the human-readable message and the failures
// count from a stored OPA decision. Tolerates any shape — a malformed
// details JSON should not break export.
func parseDetails(raw []byte) (string, int) {
	if len(raw) == 0 {
		return "", 0
	}
	var d struct {
		Message  string           `json:"message"`
		Failures []map[string]any `json:"failures"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", 0
	}
	return d.Message, len(d.Failures)
}
