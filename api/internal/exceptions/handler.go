// Package exceptions exposes the exceptions table over HTTP.
// Exceptions acknowledge a failing control without erasing the audit
// trail: the failed evidence_items row remains intact, the matching
// active exception explains why the failure is accepted, and the
// revocation of an exception is itself recorded with actor + time.
package exceptions

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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

// Register attaches exception routes to a protected group.
func (h *Handler) Register(g *echo.Group) {
	g.GET("/exceptions", h.List)
	g.POST("/exceptions", h.Grant)
	g.GET("/exceptions/:id", h.Get)
	g.POST("/exceptions/:id/revoke", h.Revoke)
}

type exceptionOut struct {
	ID           uuid.UUID  `json:"id"`
	ControlID    uuid.UUID  `json:"control_id"`
	ControlCode  string     `json:"control_code"`
	ControlTitle string     `json:"control_title"`
	ResourceKey  *string    `json:"resource_key,omitempty"`
	Reason       string     `json:"reason"`
	GrantedBy    uuid.UUID  `json:"granted_by"`
	GrantedAt    time.Time  `json:"granted_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokedBy    *uuid.UUID `json:"revoked_by,omitempty"`
}

func (h *Handler) List(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	includeRevoked := c.QueryParam("include_revoked") == "true"

	args := []any{orgID}
	sql := `
		SELECT e.id, e.control_id, c.code, c.title, e.resource_key, e.reason,
		       e.granted_by, e.granted_at, e.expires_at, e.revoked_at, e.revoked_by
		FROM exceptions e
		JOIN controls c ON c.id = e.control_id
		WHERE e.org_id = $1
	`
	if !includeRevoked {
		sql += ` AND e.revoked_at IS NULL`
	}
	if controlID := c.QueryParam("control_id"); controlID != "" {
		parsed, err := uuid.Parse(controlID)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid control_id")
		}
		sql += ` AND e.control_id = $2`
		args = append(args, parsed)
	}
	sql += ` ORDER BY e.granted_at DESC`

	rows, err := h.pool.Query(c.Request().Context(), sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []exceptionOut{}
	for rows.Next() {
		o, err := scanOne(rows)
		if err != nil {
			return err
		}
		out = append(out, o)
	}
	return c.JSON(http.StatusOK, map[string]any{"exceptions": out})
}

func (h *Handler) Get(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	o, err := h.getByID(c.Request().Context(), orgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "exception not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, o)
}

type grantIn struct {
	ControlID   uuid.UUID  `json:"control_id"`
	Reason      string     `json:"reason"`
	ResourceKey string     `json:"resource_key,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

func (h *Handler) Grant(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)

	var in grantIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if in.ControlID == uuid.Nil {
		return echo.NewHTTPError(http.StatusBadRequest, "control_id is required")
	}
	if in.Reason == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "reason is required")
	}

	// Verify the control belongs to a framework the org has enabled. The
	// FK alone would let an admin grant exceptions against arbitrary
	// controls; this scopes them to the org's actual audit surface.
	var ok bool
	err := h.pool.QueryRow(c.Request().Context(), `
		SELECT EXISTS (
			SELECT 1 FROM controls c
			JOIN org_frameworks ofw ON ofw.framework_id = c.framework_id
			WHERE c.id = $1 AND ofw.org_id = $2
		)
	`, in.ControlID, orgID).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "control is not part of any enabled framework for this org")
	}

	var id uuid.UUID
	err = h.pool.QueryRow(c.Request().Context(), `
		INSERT INTO exceptions (org_id, control_id, resource_key, reason, granted_by, expires_at)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6)
		RETURNING id
	`, orgID, in.ControlID, in.ResourceKey, in.Reason, userID, in.ExpiresAt).Scan(&id)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"control_id":   in.ControlID,
		"resource_key": in.ResourceKey,
		"reason":       in.Reason,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "exception.granted",
		ResourceID:   id.String(),
		ResourceType: "exception",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	o, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, o)
}

func (h *Handler) Revoke(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	tag, err := h.pool.Exec(c.Request().Context(), `
		UPDATE exceptions
		SET revoked_at = now(), revoked_by = $1
		WHERE org_id = $2 AND id = $3 AND revoked_at IS NULL
	`, userID, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "exception not found or already revoked")
	}

	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "exception.revoked",
		ResourceID:   id.String(),
		ResourceType: "exception",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
	})

	o, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, o)
}

func (h *Handler) getByID(ctx context.Context, orgID, id uuid.UUID) (exceptionOut, error) {
	row := h.pool.QueryRow(ctx, `
		SELECT e.id, e.control_id, c.code, c.title, e.resource_key, e.reason,
		       e.granted_by, e.granted_at, e.expires_at, e.revoked_at, e.revoked_by
		FROM exceptions e
		JOIN controls c ON c.id = e.control_id
		WHERE e.org_id = $1 AND e.id = $2
	`, orgID, id)
	return scanOne(row)
}

type singleRow interface {
	Scan(dest ...any) error
}

func scanOne(r singleRow) (exceptionOut, error) {
	var o exceptionOut
	err := r.Scan(
		&o.ID, &o.ControlID, &o.ControlCode, &o.ControlTitle,
		&o.ResourceKey, &o.Reason,
		&o.GrantedBy, &o.GrantedAt, &o.ExpiresAt, &o.RevokedAt, &o.RevokedBy,
	)
	return o, err
}
