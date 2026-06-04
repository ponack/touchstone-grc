// Package personnel exposes the personnel register over HTTP.
//
// Personnel are the workforce members whose access to in-scope
// systems is governed by the audited control set. The register is
// the foundational Phase 7 GRC table — assets, vendors, and risks
// all point at a personnel row as the owner of a record.
//
// All mutations are recorded in the audit log. Auditor-role members
// can list and view but cannot create / update / delete; the route
// table wires RequireOrgRole("admin", "member") onto the writes.
package personnel

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

// Register attaches personnel routes. Read endpoints are open to any
// org member (auditor included); mutating endpoints require admin or
// member role.
func (h *Handler) Register(g *echo.Group) {
	g.GET("/personnel", h.List, auth.RequireOrgRole(h.pool))
	g.GET("/personnel/:id", h.Get, auth.RequireOrgRole(h.pool))
	g.POST("/personnel", h.Create, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.PATCH("/personnel/:id", h.Update, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.DELETE("/personnel/:id", h.Delete, auth.RequireOrgRole(h.pool, "admin", "member"))
}

type personOut struct {
	ID         uuid.UUID  `json:"id"`
	FullName   string     `json:"full_name"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	Department *string    `json:"department,omitempty"`
	ManagerID  *uuid.UUID `json:"manager_id,omitempty"`
	StartDate  time.Time  `json:"start_date"`
	EndDate    *time.Time `json:"end_date,omitempty"`
	Status     string     `json:"status"`
	Notes      *string    `json:"notes,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type personIn struct {
	FullName   string     `json:"full_name"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	Department string     `json:"department,omitempty"`
	ManagerID  *uuid.UUID `json:"manager_id,omitempty"`
	StartDate  *time.Time `json:"start_date,omitempty"`
	EndDate    *time.Time `json:"end_date,omitempty"`
	Status     string     `json:"status,omitempty"`
	Notes      string     `json:"notes,omitempty"`
}

var validStatuses = map[string]struct{}{
	"active":     {},
	"on_leave":   {},
	"terminated": {},
}

func (h *Handler) List(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)

	args := []any{orgID}
	sql := `
		SELECT id, full_name, email, role, department, manager_id,
		       start_date, end_date, status, notes, created_at, updated_at
		FROM personnel
		WHERE org_id = $1
	`
	if status := c.QueryParam("status"); status != "" {
		if _, ok := validStatuses[status]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid status filter")
		}
		sql += ` AND status = $2`
		args = append(args, status)
	}
	sql += ` ORDER BY full_name ASC`

	rows, err := h.pool.Query(c.Request().Context(), sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []personOut{}
	for rows.Next() {
		p, err := scanOne(rows)
		if err != nil {
			return err
		}
		out = append(out, p)
	}
	return c.JSON(http.StatusOK, map[string]any{"personnel": out})
}

func (h *Handler) Get(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	p, err := h.getByID(c.Request().Context(), orgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "person not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, p)
}

func (h *Handler) Create(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)

	var in personIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if in.FullName == "" || in.Email == "" || in.Role == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "full_name, email, role are required")
	}
	if in.StartDate == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "start_date is required")
	}
	status := in.Status
	if status == "" {
		status = "active"
	}
	if _, ok := validStatuses[status]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	if status == "terminated" && in.EndDate == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "end_date is required when status is terminated")
	}
	if err := h.validateManager(c.Request().Context(), orgID, in.ManagerID); err != nil {
		return err
	}

	var id uuid.UUID
	err := h.pool.QueryRow(c.Request().Context(), `
		INSERT INTO personnel
		    (org_id, full_name, email, role, department, manager_id,
		     start_date, end_date, status, notes, created_by)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, $9, NULLIF($10, ''), $11)
		RETURNING id
	`, orgID, in.FullName, in.Email, in.Role, in.Department, in.ManagerID,
		in.StartDate, in.EndDate, status, in.Notes, userID).Scan(&id)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"email":      in.Email,
		"role":       in.Role,
		"status":     status,
		"start_date": in.StartDate,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "personnel.created",
		ResourceID:   id.String(),
		ResourceType: "personnel",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	p, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, p)
}

func (h *Handler) Update(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	existing, err := h.getByID(c.Request().Context(), orgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "person not found")
	}
	if err != nil {
		return err
	}

	var in personIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	merged := mergeUpdate(existing, in)
	if merged.Status == "terminated" && merged.EndDate == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "end_date is required when status is terminated")
	}
	if _, ok := validStatuses[merged.Status]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	if err := h.validateManager(c.Request().Context(), orgID, merged.ManagerID); err != nil {
		return err
	}
	if merged.ManagerID != nil && *merged.ManagerID == id {
		return echo.NewHTTPError(http.StatusBadRequest, "manager_id may not be the person itself")
	}

	_, err = h.pool.Exec(c.Request().Context(), `
		UPDATE personnel
		SET full_name = $3,
		    email      = $4,
		    role       = $5,
		    department = $6,
		    manager_id = $7,
		    start_date = $8,
		    end_date   = $9,
		    status     = $10,
		    notes      = $11,
		    updated_at = now()
		WHERE org_id = $1 AND id = $2
	`, orgID, id, merged.FullName, merged.Email, merged.Role,
		merged.Department, merged.ManagerID, merged.StartDate,
		merged.EndDate, merged.Status, merged.Notes)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"email":  merged.Email,
		"status": merged.Status,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "personnel.updated",
		ResourceID:   id.String(),
		ResourceType: "personnel",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	p, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, p)
}

func (h *Handler) Delete(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	tag, err := h.pool.Exec(c.Request().Context(),
		`DELETE FROM personnel WHERE org_id = $1 AND id = $2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "person not found")
	}

	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "personnel.deleted",
		ResourceID:   id.String(),
		ResourceType: "personnel",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
	})
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) validateManager(ctx context.Context, orgID uuid.UUID, managerID *uuid.UUID) error {
	if managerID == nil {
		return nil
	}
	var ok bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM personnel WHERE id = $1 AND org_id = $2)`,
		*managerID, orgID).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "manager_id does not reference a person in this org")
	}
	return nil
}

func (h *Handler) getByID(ctx context.Context, orgID, id uuid.UUID) (personOut, error) {
	row := h.pool.QueryRow(ctx, `
		SELECT id, full_name, email, role, department, manager_id,
		       start_date, end_date, status, notes, created_at, updated_at
		FROM personnel
		WHERE org_id = $1 AND id = $2
	`, orgID, id)
	return scanOne(row)
}

type singleRow interface {
	Scan(dest ...any) error
}

func scanOne(r singleRow) (personOut, error) {
	var p personOut
	err := r.Scan(
		&p.ID, &p.FullName, &p.Email, &p.Role, &p.Department, &p.ManagerID,
		&p.StartDate, &p.EndDate, &p.Status, &p.Notes,
		&p.CreatedAt, &p.UpdatedAt,
	)
	return p, err
}

// mergeUpdate returns a personOut whose fields come from `in` when
// the caller set them, and from `existing` otherwise. Strings use
// the empty string as sentinel; pointers stay nil-meaningful.
func mergeUpdate(existing personOut, in personIn) personOut {
	out := existing
	if in.FullName != "" {
		out.FullName = in.FullName
	}
	if in.Email != "" {
		out.Email = in.Email
	}
	if in.Role != "" {
		out.Role = in.Role
	}
	if in.Department != "" {
		d := in.Department
		out.Department = &d
	}
	if in.ManagerID != nil {
		out.ManagerID = in.ManagerID
	}
	if in.StartDate != nil {
		out.StartDate = *in.StartDate
	}
	if in.EndDate != nil {
		out.EndDate = in.EndDate
	}
	if in.Status != "" {
		out.Status = in.Status
	}
	if in.Notes != "" {
		n := in.Notes
		out.Notes = &n
	}
	return out
}
