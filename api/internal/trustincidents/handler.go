// Package trustincidents manages recorded security / availability
// events the org can surface on the public Trust Center.
//
// Admin endpoints under /api/v1/trust-incidents handle CRUD. The
// public trust-center endpoint (in package trustcenter) consults
// the trust_incidents table directly when show_incidents=true; this
// package owns the table and the admin write path only.
//
// Maps to SOC 2 CC7.4 (incident response) + CC2.3 (external
// communication during incidents) and ISO/IEC 27001:2022 A.5.24-26
// (information security incident management).
package trustincidents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	g.GET("/trust-incidents", h.List, auth.RequireOrgRole(h.pool))
	g.GET("/trust-incidents/:id", h.Get, auth.RequireOrgRole(h.pool))
	g.POST("/trust-incidents", h.Create, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.PATCH("/trust-incidents/:id", h.Update, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.DELETE("/trust-incidents/:id", h.Delete, auth.RequireOrgRole(h.pool, "admin", "member"))
}

type incidentOut struct {
	ID             uuid.UUID  `json:"id"`
	Title          string     `json:"title"`
	Status         string     `json:"status"`
	Severity       string     `json:"severity"`
	OccurredAt     time.Time  `json:"occurred_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	Summary        *string    `json:"summary,omitempty"`
	PublicResponse *string    `json:"public_response,omitempty"`
	IsPublic       bool       `json:"is_public"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type incidentIn struct {
	Title          string     `json:"title"`
	Status         string     `json:"status,omitempty"`
	Severity       string     `json:"severity,omitempty"`
	OccurredAt     *time.Time `json:"occurred_at,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	Summary        string     `json:"summary,omitempty"`
	PublicResponse string     `json:"public_response,omitempty"`
	IsPublic       *bool      `json:"is_public,omitempty"`
}

var validStatuses = map[string]struct{}{
	"ongoing":    {},
	"monitoring": {},
	"resolved":   {},
}

var validSeverities = map[string]struct{}{
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

const baseSelect = `
	SELECT id, title, status, severity,
	       occurred_at, resolved_at,
	       summary, public_response, is_public,
	       created_at, updated_at
	FROM trust_incidents
`

func (h *Handler) List(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)

	args := []any{orgID}
	sql := baseSelect + ` WHERE org_id = $1`
	if s := c.QueryParam("status"); s != "" {
		if _, ok := validStatuses[s]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid status filter")
		}
		args = append(args, s)
		sql += fmt.Sprintf(` AND status = $%d`, len(args))
	}
	sql += ` ORDER BY occurred_at DESC`

	rows, err := h.pool.Query(c.Request().Context(), sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []incidentOut{}
	for rows.Next() {
		i, err := scanOne(rows)
		if err != nil {
			return err
		}
		out = append(out, i)
	}
	return c.JSON(http.StatusOK, map[string]any{"incidents": out})
}

func (h *Handler) Get(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	i, err := h.byID(c.Request().Context(), orgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "incident not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, i)
}

func (h *Handler) Create(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)

	var in incidentIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	in.Title = strings.TrimSpace(in.Title)
	if in.Title == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "title is required")
	}
	status, severity, err := validateEnums(in)
	if err != nil {
		return err
	}
	if status == "resolved" && in.ResolvedAt == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "resolved_at is required when status is resolved")
	}
	occurred := time.Now().UTC()
	if in.OccurredAt != nil {
		occurred = *in.OccurredAt
	}
	isPublic := false
	if in.IsPublic != nil {
		isPublic = *in.IsPublic
	}

	var id uuid.UUID
	err = h.pool.QueryRow(c.Request().Context(), `
		INSERT INTO trust_incidents
		    (org_id, title, status, severity, occurred_at, resolved_at,
		     summary, public_response, is_public, created_by)
		VALUES ($1, $2, $3, $4, $5, $6,
		        NULLIF($7, ''), NULLIF($8, ''), $9, $10)
		RETURNING id
	`, orgID, in.Title, status, severity, occurred, in.ResolvedAt,
		in.Summary, in.PublicResponse, isPublic, userID).Scan(&id)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"title":     in.Title,
		"status":    status,
		"severity":  severity,
		"is_public": isPublic,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "trust_incident.created",
		ResourceID:   id.String(),
		ResourceType: "trust_incident",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	i, err := h.byID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, i)
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
		return echo.NewHTTPError(http.StatusNotFound, "incident not found")
	}
	if err != nil {
		return err
	}

	var in incidentIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	merged := mergeUpdate(existing, in)

	if _, ok := validStatuses[merged.Status]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	if _, ok := validSeverities[merged.Severity]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid severity")
	}
	if merged.Status == "resolved" && merged.ResolvedAt == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "resolved_at is required when status is resolved")
	}

	_, err = h.pool.Exec(c.Request().Context(), `
		UPDATE trust_incidents
		SET title           = $3,
		    status          = $4,
		    severity        = $5,
		    occurred_at     = $6,
		    resolved_at     = $7,
		    summary         = $8,
		    public_response = $9,
		    is_public       = $10,
		    updated_at      = now()
		WHERE org_id = $1 AND id = $2
	`, orgID, id, merged.Title, merged.Status, merged.Severity,
		merged.OccurredAt, merged.ResolvedAt,
		merged.Summary, merged.PublicResponse, merged.IsPublic)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"title":     merged.Title,
		"status":    merged.Status,
		"is_public": merged.IsPublic,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "trust_incident.updated",
		ResourceID:   id.String(),
		ResourceType: "trust_incident",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	i, err := h.byID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, i)
}

func (h *Handler) Delete(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	tag, err := h.pool.Exec(c.Request().Context(),
		`DELETE FROM trust_incidents WHERE org_id = $1 AND id = $2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "incident not found")
	}

	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "trust_incident.deleted",
		ResourceID:   id.String(),
		ResourceType: "trust_incident",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
	})
	return c.NoContent(http.StatusNoContent)
}

func validateEnums(in incidentIn) (string, string, error) {
	status := in.Status
	if status == "" {
		status = "ongoing"
	}
	if _, ok := validStatuses[status]; !ok {
		return "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	severity := in.Severity
	if severity == "" {
		severity = "medium"
	}
	if _, ok := validSeverities[severity]; !ok {
		return "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid severity")
	}
	return status, severity, nil
}

func (h *Handler) byID(ctx context.Context, orgID, id uuid.UUID) (incidentOut, error) {
	row := h.pool.QueryRow(ctx, baseSelect+` WHERE org_id = $1 AND id = $2`, orgID, id)
	return scanOne(row)
}

type singleRow interface {
	Scan(dest ...any) error
}

func scanOne(r singleRow) (incidentOut, error) {
	var i incidentOut
	err := r.Scan(
		&i.ID, &i.Title, &i.Status, &i.Severity,
		&i.OccurredAt, &i.ResolvedAt,
		&i.Summary, &i.PublicResponse, &i.IsPublic,
		&i.CreatedAt, &i.UpdatedAt,
	)
	return i, err
}

// mergeUpdate behaves like the other GRC handlers: empty strings on
// `in` mean "no change"; explicit values override `existing`. Split
// into helpers to keep cyclomatic complexity bounded.
func mergeUpdate(existing incidentOut, in incidentIn) incidentOut {
	out := existing
	mergeIdentity(&out, in)
	mergeTimeline(&out, in)
	mergeContent(&out, in)
	return out
}

func mergeIdentity(out *incidentOut, in incidentIn) {
	if in.Title != "" {
		out.Title = strings.TrimSpace(in.Title)
	}
	if in.Status != "" {
		out.Status = in.Status
	}
	if in.Severity != "" {
		out.Severity = in.Severity
	}
}

func mergeTimeline(out *incidentOut, in incidentIn) {
	if in.OccurredAt != nil {
		out.OccurredAt = *in.OccurredAt
	}
	if in.ResolvedAt != nil {
		out.ResolvedAt = in.ResolvedAt
	}
}

func mergeContent(out *incidentOut, in incidentIn) {
	if in.Summary != "" {
		s := in.Summary
		out.Summary = &s
	}
	if in.PublicResponse != "" {
		r := in.PublicResponse
		out.PublicResponse = &r
	}
	if in.IsPublic != nil {
		out.IsPublic = *in.IsPublic
	}
}
