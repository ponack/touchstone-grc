// Package assets exposes the asset inventory register over HTTP.
//
// An asset is anything within the audited boundary the organization
// tracks for compliance scope — applications, services, databases,
// code repositories, data stores, cloud accounts, infrastructure
// elements, and the occasional device on a hybrid estate. Each
// asset carries an owner (a row in the personnel register), a
// classification, an environment tag, a criticality, and a status.
//
// Maps to ISO/IEC 27001:2022 A.5.9 + A.5.12 + SOC 2 CC6.1.
//
// Auditor-role members see the register read-only; admin / member
// roles can create, update, delete.
package assets

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
	g.GET("/assets", h.List, auth.RequireOrgRole(h.pool))
	g.GET("/assets/:id", h.Get, auth.RequireOrgRole(h.pool))
	g.POST("/assets", h.Create, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.PATCH("/assets/:id", h.Update, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.DELETE("/assets/:id", h.Delete, auth.RequireOrgRole(h.pool, "admin", "member"))
}

type assetOut struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	AssetType      string     `json:"asset_type"`
	Classification *string    `json:"classification,omitempty"`
	Environment    string     `json:"environment"`
	Criticality    string     `json:"criticality"`
	Status         string     `json:"status"`
	OwnerID        *uuid.UUID `json:"owner_id,omitempty"`
	OwnerName      *string    `json:"owner_name,omitempty"`
	Description    *string    `json:"description,omitempty"`
	ExternalRef    *string    `json:"external_ref,omitempty"`
	Tags           []string   `json:"tags"`
	Notes          *string    `json:"notes,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type assetIn struct {
	Name           string     `json:"name"`
	AssetType      string     `json:"asset_type"`
	Classification string     `json:"classification,omitempty"`
	Environment    string     `json:"environment,omitempty"`
	Criticality    string     `json:"criticality,omitempty"`
	Status         string     `json:"status,omitempty"`
	OwnerID        *uuid.UUID `json:"owner_id,omitempty"`
	Description    string     `json:"description,omitempty"`
	ExternalRef    string     `json:"external_ref,omitempty"`
	Tags           []string   `json:"tags,omitempty"`
	Notes          string     `json:"notes,omitempty"`
}

var validAssetTypes = map[string]struct{}{
	"application":    {},
	"service":        {},
	"database":       {},
	"repository":     {},
	"data_store":     {},
	"cloud_account":  {},
	"infrastructure": {},
	"device":         {},
	"other":          {},
}

var validClassifications = map[string]struct{}{
	"public":       {},
	"internal":     {},
	"confidential": {},
	"restricted":   {},
}

var validEnvironments = map[string]struct{}{
	"production":  {},
	"staging":     {},
	"development": {},
	"other":       {},
}

var validCriticalities = map[string]struct{}{
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

var validAssetStatuses = map[string]struct{}{
	"active":         {},
	"planned":        {},
	"decommissioned": {},
}

const baseSelect = `
	SELECT a.id, a.name, a.asset_type, a.classification, a.environment,
	       a.criticality, a.status, a.owner_id, p.full_name AS owner_name,
	       a.description, a.external_ref, a.tags, a.notes,
	       a.created_at, a.updated_at
	FROM assets a
	LEFT JOIN personnel p ON p.id = a.owner_id
`

func (h *Handler) List(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)

	args := []any{orgID}
	sql := baseSelect + ` WHERE a.org_id = $1`
	if t := c.QueryParam("asset_type"); t != "" {
		if _, ok := validAssetTypes[t]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid asset_type filter")
		}
		args = append(args, t)
		sql += ` AND a.asset_type = $2`
	}
	if s := c.QueryParam("status"); s != "" {
		if _, ok := validAssetStatuses[s]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid status filter")
		}
		args = append(args, s)
		sql += fmt.Sprintf(` AND a.status = $%d`, len(args))
	}
	sql += ` ORDER BY a.name ASC`

	rows, err := h.pool.Query(c.Request().Context(), sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []assetOut{}
	for rows.Next() {
		a, err := scanOne(rows)
		if err != nil {
			return err
		}
		out = append(out, a)
	}
	return c.JSON(http.StatusOK, map[string]any{"assets": out})
}

func (h *Handler) Get(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	a, err := h.getByID(c.Request().Context(), orgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "asset not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, a)
}

func (h *Handler) Create(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)

	var in assetIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || in.AssetType == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name and asset_type are required")
	}
	env, crit, status, err := validateCreate(in)
	if err != nil {
		return err
	}
	if err := h.validateOwner(c.Request().Context(), orgID, in.OwnerID); err != nil {
		return err
	}
	tags := normalizeTags(in.Tags)

	var classArg any
	if in.Classification != "" {
		classArg = in.Classification
	}

	var id uuid.UUID
	err = h.pool.QueryRow(c.Request().Context(), `
		INSERT INTO assets
		    (org_id, name, asset_type, classification, environment, criticality,
		     status, owner_id, description, external_ref, tags, notes, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), NULLIF($10, ''), $11, NULLIF($12, ''), $13)
		RETURNING id
	`, orgID, in.Name, in.AssetType, classArg, env, crit, status,
		in.OwnerID, in.Description, in.ExternalRef, tags, in.Notes, userID).Scan(&id)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"name":       in.Name,
		"asset_type": in.AssetType,
		"status":     status,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "asset.created",
		ResourceID:   id.String(),
		ResourceType: "asset",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	a, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, a)
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
		return echo.NewHTTPError(http.StatusNotFound, "asset not found")
	}
	if err != nil {
		return err
	}

	var in assetIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	merged := mergeUpdate(existing, in)

	if _, ok := validAssetTypes[merged.AssetType]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid asset_type")
	}
	if merged.Classification != nil {
		if _, ok := validClassifications[*merged.Classification]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid classification")
		}
	}
	if _, ok := validEnvironments[merged.Environment]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid environment")
	}
	if _, ok := validCriticalities[merged.Criticality]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid criticality")
	}
	if _, ok := validAssetStatuses[merged.Status]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	if err := h.validateOwner(c.Request().Context(), orgID, merged.OwnerID); err != nil {
		return err
	}

	_, err = h.pool.Exec(c.Request().Context(), `
		UPDATE assets
		SET name           = $3,
		    asset_type     = $4,
		    classification = $5,
		    environment    = $6,
		    criticality    = $7,
		    status         = $8,
		    owner_id       = $9,
		    description    = $10,
		    external_ref   = $11,
		    tags           = $12,
		    notes          = $13,
		    updated_at     = now()
		WHERE org_id = $1 AND id = $2
	`, orgID, id, merged.Name, merged.AssetType, merged.Classification,
		merged.Environment, merged.Criticality, merged.Status, merged.OwnerID,
		merged.Description, merged.ExternalRef, merged.Tags, merged.Notes)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"name":   merged.Name,
		"status": merged.Status,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "asset.updated",
		ResourceID:   id.String(),
		ResourceType: "asset",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	a, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, a)
}

func (h *Handler) Delete(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	tag, err := h.pool.Exec(c.Request().Context(),
		`DELETE FROM assets WHERE org_id = $1 AND id = $2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "asset not found")
	}

	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "asset.deleted",
		ResourceID:   id.String(),
		ResourceType: "asset",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
	})
	return c.NoContent(http.StatusNoContent)
}

// validateCreate normalizes optional enum fields, applies defaults
// (env=production, crit=medium, status=active), and validates every
// enum the request actually carries. Returns the resolved env / crit
// / status so the caller writes the row from a single source of
// truth.
func validateCreate(in assetIn) (string, string, string, error) {
	if _, ok := validAssetTypes[in.AssetType]; !ok {
		return "", "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid asset_type")
	}
	if in.Classification != "" {
		if _, ok := validClassifications[in.Classification]; !ok {
			return "", "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid classification")
		}
	}
	env := in.Environment
	if env == "" {
		env = "production"
	}
	if _, ok := validEnvironments[env]; !ok {
		return "", "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid environment")
	}
	crit := in.Criticality
	if crit == "" {
		crit = "medium"
	}
	if _, ok := validCriticalities[crit]; !ok {
		return "", "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid criticality")
	}
	status := in.Status
	if status == "" {
		status = "active"
	}
	if _, ok := validAssetStatuses[status]; !ok {
		return "", "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	return env, crit, status, nil
}

func (h *Handler) validateOwner(ctx context.Context, orgID uuid.UUID, ownerID *uuid.UUID) error {
	if ownerID == nil {
		return nil
	}
	var ok bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM personnel WHERE id = $1 AND org_id = $2)`,
		*ownerID, orgID).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "owner_id does not reference a person in this org")
	}
	return nil
}

func (h *Handler) getByID(ctx context.Context, orgID, id uuid.UUID) (assetOut, error) {
	row := h.pool.QueryRow(ctx, baseSelect+` WHERE a.org_id = $1 AND a.id = $2`, orgID, id)
	return scanOne(row)
}

type singleRow interface {
	Scan(dest ...any) error
}

func scanOne(r singleRow) (assetOut, error) {
	var a assetOut
	err := r.Scan(
		&a.ID, &a.Name, &a.AssetType, &a.Classification, &a.Environment,
		&a.Criticality, &a.Status, &a.OwnerID, &a.OwnerName,
		&a.Description, &a.ExternalRef, &a.Tags, &a.Notes,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if a.Tags == nil {
		a.Tags = []string{}
	}
	return a, err
}

// mergeUpdate returns an assetOut whose fields come from `in` when
// the caller set them, and from `existing` otherwise. Classification
// is special: callers pass the literal string "none" to clear it
// (sending an empty string is ambiguous with "do not change") —
// matching the form's reset semantics.
func mergeUpdate(existing assetOut, in assetIn) assetOut {
	out := existing
	if in.Name != "" {
		out.Name = strings.TrimSpace(in.Name)
	}
	if in.AssetType != "" {
		out.AssetType = in.AssetType
	}
	switch in.Classification {
	case "":
		// no change
	case "none":
		out.Classification = nil
	default:
		c := in.Classification
		out.Classification = &c
	}
	if in.Environment != "" {
		out.Environment = in.Environment
	}
	if in.Criticality != "" {
		out.Criticality = in.Criticality
	}
	if in.Status != "" {
		out.Status = in.Status
	}
	if in.OwnerID != nil {
		out.OwnerID = in.OwnerID
	}
	if in.Description != "" {
		d := in.Description
		out.Description = &d
	}
	if in.ExternalRef != "" {
		r := in.ExternalRef
		out.ExternalRef = &r
	}
	if in.Tags != nil {
		out.Tags = normalizeTags(in.Tags)
	}
	if in.Notes != "" {
		n := in.Notes
		out.Notes = &n
	}
	return out
}

// normalizeTags trims whitespace, drops empties, and lower-cases.
// Stable order so list payloads diff cleanly in audit_events context.
func normalizeTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}
