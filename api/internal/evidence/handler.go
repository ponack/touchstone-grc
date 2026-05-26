// Package evidence exposes the evidence_items rows produced by scans.
// Two endpoints: list-by-scan and single-detail. Both are org-scoped
// via the existing auth middleware.
package evidence

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

// Register wires:
//
//	GET /api/v1/scans/:id/evidence — list this scan's evidence items
//	GET /api/v1/evidence/latest    — most recent evidence per control
//	                                  across enabled frameworks for the org
//	GET /api/v1/evidence/:id       — full detail including decision JSON
func (h *Handler) Register(g *echo.Group) {
	g.GET("/scans/:id/evidence", h.ListForScan)
	g.GET("/evidence/latest", h.Latest)
	g.GET("/evidence/:id", h.Get)
}

type latestRow struct {
	ID            uuid.UUID `json:"id"`
	ScanID        uuid.UUID `json:"scan_id"`
	ControlID     uuid.UUID `json:"control_id"`
	ControlCode   string    `json:"control_code"`
	ControlTitle  string    `json:"control_title"`
	FrameworkCode string    `json:"framework_code"`
	Status        string    `json:"status"`
	CollectedAt   time.Time `json:"collected_at"`
}

func (h *Handler) Latest(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)

	rows, err := h.pool.Query(c.Request().Context(), `
		SELECT DISTINCT ON (e.control_id)
		       e.id, e.scan_id, e.control_id, c.code, c.title, f.code,
		       e.status, e.collected_at
		FROM evidence_items e
		JOIN controls c        ON c.id = e.control_id
		JOIN frameworks f      ON f.id = c.framework_id
		JOIN org_frameworks of ON of.framework_id = f.id AND of.org_id = e.org_id
		WHERE e.org_id = $1
		ORDER BY e.control_id, e.collected_at DESC
	`, orgID)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []latestRow{}
	for rows.Next() {
		var r latestRow
		if err := rows.Scan(&r.ID, &r.ScanID, &r.ControlID, &r.ControlCode, &r.ControlTitle, &r.FrameworkCode, &r.Status, &r.CollectedAt); err != nil {
			return err
		}
		out = append(out, r)
	}
	return c.JSON(http.StatusOK, map[string]any{"evidence": out})
}

type summary struct {
	ID           uuid.UUID `json:"id"`
	ControlID    uuid.UUID `json:"control_id"`
	ControlCode  string    `json:"control_code"`
	ControlTitle string    `json:"control_title"`
	Status       string    `json:"status"`
	CollectedAt  time.Time `json:"collected_at"`
}

type detail struct {
	ID            uuid.UUID       `json:"id"`
	ScanID        uuid.UUID       `json:"scan_id"`
	ControlID     uuid.UUID       `json:"control_id"`
	ControlCode   string          `json:"control_code"`
	ControlTitle  string          `json:"control_title"`
	FrameworkCode string          `json:"framework_code"`
	Status        string          `json:"status"`
	Details       json.RawMessage `json:"details"`
	ArtifactKey   *string         `json:"artifact_key,omitempty"`
	CollectedAt   time.Time       `json:"collected_at"`
}

func (h *Handler) ListForScan(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	scanID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	rows, err := h.pool.Query(c.Request().Context(), `
		SELECT e.id, e.control_id, c.code, c.title, e.status, e.collected_at
		FROM evidence_items e
		JOIN controls c ON c.id = e.control_id
		WHERE e.org_id = $1 AND e.scan_id = $2
		ORDER BY c.code
	`, orgID, scanID)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []summary{}
	for rows.Next() {
		var s summary
		if err := rows.Scan(&s.ID, &s.ControlID, &s.ControlCode, &s.ControlTitle, &s.Status, &s.CollectedAt); err != nil {
			return err
		}
		out = append(out, s)
	}
	return c.JSON(http.StatusOK, map[string]any{"evidence": out})
}

func (h *Handler) Get(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	var d detail
	err = h.pool.QueryRow(c.Request().Context(), `
		SELECT e.id, e.scan_id, e.control_id, c.code, c.title, f.code,
		       e.status, e.details, e.artifact_key, e.collected_at
		FROM evidence_items e
		JOIN controls c    ON c.id = e.control_id
		JOIN frameworks f  ON f.id = c.framework_id
		WHERE e.org_id = $1 AND e.id = $2
	`, orgID, id).Scan(
		&d.ID, &d.ScanID, &d.ControlID, &d.ControlCode, &d.ControlTitle,
		&d.FrameworkCode, &d.Status, &d.Details, &d.ArtifactKey, &d.CollectedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "evidence not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, d)
}
