// Package trustblocks manages named Markdown content sections the
// admin can drop onto the Trust Center. Escape hatch for org-
// specific copy (data-handling notes, SLA / uptime commitments,
// incident policy, sub-processor addendum, etc.) that doesn't fit
// the fixed framework / subprocessor / incident sections.
//
// Admin endpoints under /api/v1/trust-blocks handle CRUD + move.
// The public trust-center endpoint (in package trustcenter)
// consults trust_blocks directly when show_blocks=true.
//
// Maps loosely to SOC 2 CC2.3 (external communications) +
// ISO/IEC 27001:2022 A.5.18 (public information).
package trustblocks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	"github.com/ponack/touchstone/internal/audit"
	"github.com/ponack/touchstone/internal/auth"
)

type Handler struct {
	pool *pgxpool.Pool
}

func NewHandler(pool *pgxpool.Pool) *Handler {
	return &Handler{pool: pool}
}

func (h *Handler) Register(g *echo.Group) {
	g.GET("/trust-blocks", h.List, auth.RequireOrgRole(h.pool))
	g.GET("/trust-blocks/:id", h.Get, auth.RequireOrgRole(h.pool))
	g.POST("/trust-blocks", h.Create, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.PATCH("/trust-blocks/:id", h.Update, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.POST("/trust-blocks/:id/move", h.Move, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.DELETE("/trust-blocks/:id", h.Delete, auth.RequireOrgRole(h.pool, "admin", "member"))
}

type blockOut struct {
	ID           uuid.UUID `json:"id"`
	Heading      string    `json:"heading"`
	BodyMarkdown string    `json:"body_markdown"`
	Position     int       `json:"position"`
	IsPublic     bool      `json:"is_public"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type blockIn struct {
	Heading      string `json:"heading"`
	BodyMarkdown string `json:"body_markdown"`
	Position     *int   `json:"position,omitempty"`
	IsPublic     *bool  `json:"is_public,omitempty"`
}

type moveIn struct {
	Direction string `json:"direction"`
}

const baseSelect = `
	SELECT id, heading, body_markdown, position, is_public,
	       created_at, updated_at
	FROM trust_blocks
`

func (h *Handler) List(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	rows, err := h.pool.Query(c.Request().Context(),
		baseSelect+` WHERE org_id = $1 ORDER BY position ASC, created_at ASC`, orgID)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []blockOut{}
	for rows.Next() {
		b, err := scanOne(rows)
		if err != nil {
			return err
		}
		out = append(out, b)
	}
	return c.JSON(http.StatusOK, map[string]any{"blocks": out})
}

func (h *Handler) Get(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	b, err := h.byID(c.Request().Context(), orgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "block not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, b)
}

func (h *Handler) Create(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)

	var in blockIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	in.Heading = strings.TrimSpace(in.Heading)
	in.BodyMarkdown = strings.TrimSpace(in.BodyMarkdown)
	if in.Heading == "" || in.BodyMarkdown == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "heading and body_markdown are required")
	}
	isPublic := false
	if in.IsPublic != nil {
		isPublic = *in.IsPublic
	}

	// New blocks land at the end of the current list unless the
	// caller supplies a specific position — matches how a human
	// mental-models "add another section."
	position := 0
	if in.Position != nil {
		position = *in.Position
	} else {
		if err := h.pool.QueryRow(c.Request().Context(),
			`SELECT COALESCE(MAX(position), -1) + 1 FROM trust_blocks WHERE org_id = $1`,
			orgID).Scan(&position); err != nil {
			return err
		}
	}

	var id uuid.UUID
	err := h.pool.QueryRow(c.Request().Context(), `
		INSERT INTO trust_blocks
		    (org_id, heading, body_markdown, position, is_public, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, orgID, in.Heading, in.BodyMarkdown, position, isPublic, userID).Scan(&id)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"heading":   in.Heading,
		"is_public": isPublic,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "trust_block.created",
		ResourceID:   id.String(),
		ResourceType: "trust_block",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	b, err := h.byID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, b)
}

func (h *Handler) Update(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	existing, err := h.byID(c.Request().Context(), orgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "block not found")
	}
	if err != nil {
		return err
	}

	var in blockIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	merged := mergeUpdate(existing, in)
	if merged.Heading == "" || merged.BodyMarkdown == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "heading and body_markdown may not be empty")
	}

	_, err = h.pool.Exec(c.Request().Context(), `
		UPDATE trust_blocks
		SET heading       = $3,
		    body_markdown = $4,
		    position      = $5,
		    is_public     = $6,
		    updated_at    = now()
		WHERE org_id = $1 AND id = $2
	`, orgID, id, merged.Heading, merged.BodyMarkdown, merged.Position, merged.IsPublic)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"heading":   merged.Heading,
		"is_public": merged.IsPublic,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "trust_block.updated",
		ResourceID:   id.String(),
		ResourceType: "trust_block",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	b, err := h.byID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, b)
}

// Move swaps position with the immediate neighbor in the requested
// direction. Simpler admin UX than "type a position number." The
// swap is done in a single transaction so a concurrent Move on the
// same neighbor either wins or loses cleanly (no interleaved
// positions).
func (h *Handler) Move(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	var in moveIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if in.Direction != "up" && in.Direction != "down" {
		return echo.NewHTTPError(http.StatusBadRequest, "direction must be 'up' or 'down'")
	}

	tx, err := h.pool.Begin(c.Request().Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(c.Request().Context())

	var pos int
	if err := tx.QueryRow(c.Request().Context(),
		`SELECT position FROM trust_blocks WHERE org_id = $1 AND id = $2 FOR UPDATE`,
		orgID, id).Scan(&pos); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "block not found")
		}
		return err
	}

	// Find the neighbor row on the requested side.
	neighborSQL := `
		SELECT id, position FROM trust_blocks
		WHERE org_id = $1 AND position ` + neighborCmp(in.Direction) + ` $2
		ORDER BY position ` + neighborOrder(in.Direction) + `
		LIMIT 1
		FOR UPDATE
	`
	var neighborID uuid.UUID
	var neighborPos int
	if err := tx.QueryRow(c.Request().Context(), neighborSQL, orgID, pos).Scan(&neighborID, &neighborPos); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusBadRequest, "already at "+edgeLabel(in.Direction))
		}
		return err
	}

	// Two-hop swap avoids brief unique-index collisions in the
	// unlikely future where we add a UNIQUE(org_id, position)
	// constraint. Safe today either way.
	tmpPos := -1 - pos
	if _, err := tx.Exec(c.Request().Context(),
		`UPDATE trust_blocks SET position = $2, updated_at = now() WHERE id = $1`,
		id, tmpPos); err != nil {
		return err
	}
	if _, err := tx.Exec(c.Request().Context(),
		`UPDATE trust_blocks SET position = $2, updated_at = now() WHERE id = $1`,
		neighborID, pos); err != nil {
		return err
	}
	if _, err := tx.Exec(c.Request().Context(),
		`UPDATE trust_blocks SET position = $2, updated_at = now() WHERE id = $1`,
		id, neighborPos); err != nil {
		return err
	}
	if err := tx.Commit(c.Request().Context()); err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{"direction": in.Direction})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "trust_block.moved",
		ResourceID:   id.String(),
		ResourceType: "trust_block",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	b, err := h.byID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, b)
}

func neighborCmp(direction string) string {
	if direction == "up" {
		return "<"
	}
	return ">"
}

func neighborOrder(direction string) string {
	if direction == "up" {
		return "DESC"
	}
	return "ASC"
}

func edgeLabel(direction string) string {
	if direction == "up" {
		return "top"
	}
	return "bottom"
}

func (h *Handler) Delete(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	tag, err := h.pool.Exec(c.Request().Context(),
		`DELETE FROM trust_blocks WHERE org_id = $1 AND id = $2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "block not found")
	}

	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "trust_block.deleted",
		ResourceID:   id.String(),
		ResourceType: "trust_block",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
	})
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) byID(ctx context.Context, orgID, id uuid.UUID) (blockOut, error) {
	row := h.pool.QueryRow(ctx, baseSelect+` WHERE org_id = $1 AND id = $2`, orgID, id)
	return scanOne(row)
}

type singleRow interface {
	Scan(dest ...any) error
}

func scanOne(r singleRow) (blockOut, error) {
	var b blockOut
	err := r.Scan(&b.ID, &b.Heading, &b.BodyMarkdown, &b.Position, &b.IsPublic, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

// mergeUpdate applies the partial PATCH input to `existing`. Empty
// strings on `in` mean "no change"; explicit values override. The
// simple shape means we don't need the helper split the vendor /
// risk / incident merges use for cyclomatic reasons.
func mergeUpdate(existing blockOut, in blockIn) blockOut {
	out := existing
	if in.Heading != "" {
		out.Heading = strings.TrimSpace(in.Heading)
	}
	if in.BodyMarkdown != "" {
		out.BodyMarkdown = strings.TrimSpace(in.BodyMarkdown)
	}
	if in.Position != nil {
		out.Position = *in.Position
	}
	if in.IsPublic != nil {
		out.IsPublic = *in.IsPublic
	}
	return out
}
