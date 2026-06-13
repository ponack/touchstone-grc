// Package vendors exposes the vendor / supplier register over HTTP.
//
// Captures third-party suppliers whose services or technology fall
// inside the audited boundary. Maps to SOC 2 CC9.2 / PCI DSS 12.8 /
// ISO/IEC 27001:2022 A.5.19-22 (supplier relationships, supplier
// agreements, ICT supply chain, monitoring & review).
//
// Auditor-role members see the register read-only; admin / member
// roles can create, update, delete. Every write emits an audit row.
package vendors

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
	g.GET("/vendors", h.List, auth.RequireOrgRole(h.pool))
	g.GET("/vendors/:id", h.Get, auth.RequireOrgRole(h.pool))
	g.POST("/vendors", h.Create, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.PATCH("/vendors/:id", h.Update, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.DELETE("/vendors/:id", h.Delete, auth.RequireOrgRole(h.pool, "admin", "member"))
}

type vendorOut struct {
	ID                 uuid.UUID  `json:"id"`
	Name               string     `json:"name"`
	VendorType         string     `json:"vendor_type"`
	Criticality        string     `json:"criticality"`
	Status             string     `json:"status"`
	DataClassification *string    `json:"data_classification,omitempty"`
	OwnerID            *uuid.UUID `json:"owner_id,omitempty"`
	OwnerName          *string    `json:"owner_name,omitempty"`
	Website            *string    `json:"website,omitempty"`
	ContactName        *string    `json:"contact_name,omitempty"`
	ContactEmail       *string    `json:"contact_email,omitempty"`
	Description        *string    `json:"description,omitempty"`
	OnboardedDate      *time.Time `json:"onboarded_date,omitempty"`
	OffboardedDate     *time.Time `json:"offboarded_date,omitempty"`
	AssuranceReport    *string    `json:"assurance_report,omitempty"`
	LastReviewDate     *time.Time `json:"last_review_date,omitempty"`
	NextReviewDate     *time.Time `json:"next_review_date,omitempty"`
	Tags               []string   `json:"tags"`
	Notes              *string    `json:"notes,omitempty"`
	TrustCenterPublic  bool       `json:"trust_center_public"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type vendorIn struct {
	Name               string     `json:"name"`
	VendorType         string     `json:"vendor_type"`
	Criticality        string     `json:"criticality,omitempty"`
	Status             string     `json:"status,omitempty"`
	DataClassification string     `json:"data_classification,omitempty"`
	OwnerID            *uuid.UUID `json:"owner_id,omitempty"`
	Website            string     `json:"website,omitempty"`
	ContactName        string     `json:"contact_name,omitempty"`
	ContactEmail       string     `json:"contact_email,omitempty"`
	Description        string     `json:"description,omitempty"`
	OnboardedDate      *time.Time `json:"onboarded_date,omitempty"`
	OffboardedDate     *time.Time `json:"offboarded_date,omitempty"`
	AssuranceReport    string     `json:"assurance_report,omitempty"`
	LastReviewDate     *time.Time `json:"last_review_date,omitempty"`
	NextReviewDate     *time.Time `json:"next_review_date,omitempty"`
	Tags               []string   `json:"tags,omitempty"`
	Notes              string     `json:"notes,omitempty"`
	TrustCenterPublic  *bool      `json:"trust_center_public,omitempty"`
}

var validVendorTypes = map[string]struct{}{
	"saas":                  {},
	"paas":                  {},
	"iaas":                  {},
	"processor":             {},
	"subprocessor":          {},
	"hardware":              {},
	"professional_services": {},
	"other":                 {},
}

var validClassifications = map[string]struct{}{
	"public":       {},
	"internal":     {},
	"confidential": {},
	"restricted":   {},
}

var validCriticalities = map[string]struct{}{
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

var validVendorStatuses = map[string]struct{}{
	"prospective": {},
	"active":      {},
	"terminated":  {},
}

const baseSelect = `
	SELECT v.id, v.name, v.vendor_type, v.criticality, v.status,
	       v.data_classification, v.owner_id, p.full_name AS owner_name,
	       v.website, v.contact_name, v.contact_email, v.description,
	       v.onboarded_date, v.offboarded_date, v.assurance_report,
	       v.last_review_date, v.next_review_date, v.tags, v.notes,
	       v.trust_center_public,
	       v.created_at, v.updated_at
	FROM vendors v
	LEFT JOIN personnel p ON p.id = v.owner_id
`

func (h *Handler) List(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)

	args := []any{orgID}
	sql := baseSelect + ` WHERE v.org_id = $1`
	if t := c.QueryParam("vendor_type"); t != "" {
		if _, ok := validVendorTypes[t]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid vendor_type filter")
		}
		args = append(args, t)
		sql += fmt.Sprintf(` AND v.vendor_type = $%d`, len(args))
	}
	if s := c.QueryParam("status"); s != "" {
		if _, ok := validVendorStatuses[s]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid status filter")
		}
		args = append(args, s)
		sql += fmt.Sprintf(` AND v.status = $%d`, len(args))
	}
	if r := c.QueryParam("review_due"); r == "true" {
		// "Due" = next_review_date is null OR on/before today. Auditors
		// scanning for cadence gaps reach for this first.
		sql += ` AND (v.next_review_date IS NULL OR v.next_review_date <= CURRENT_DATE)`
	}
	sql += ` ORDER BY v.name ASC`

	rows, err := h.pool.Query(c.Request().Context(), sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []vendorOut{}
	for rows.Next() {
		v, err := scanOne(rows)
		if err != nil {
			return err
		}
		out = append(out, v)
	}
	return c.JSON(http.StatusOK, map[string]any{"vendors": out})
}

func (h *Handler) Get(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	v, err := h.getByID(c.Request().Context(), orgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "vendor not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, v)
}

func (h *Handler) Create(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)

	var in vendorIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || in.VendorType == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name and vendor_type are required")
	}
	crit, status, err := validateEnums(in)
	if err != nil {
		return err
	}
	if status == "terminated" && in.OffboardedDate == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "offboarded_date is required when status is terminated")
	}
	if err := h.validateOwner(c.Request().Context(), orgID, in.OwnerID); err != nil {
		return err
	}
	tags := normalizeTags(in.Tags)

	var classArg any
	if in.DataClassification != "" {
		classArg = in.DataClassification
	}

	trustPub := false
	if in.TrustCenterPublic != nil {
		trustPub = *in.TrustCenterPublic
	}

	var id uuid.UUID
	err = h.pool.QueryRow(c.Request().Context(), `
		INSERT INTO vendors
		    (org_id, name, vendor_type, criticality, status, data_classification,
		     owner_id, website, contact_name, contact_email, description,
		     onboarded_date, offboarded_date, assurance_report,
		     last_review_date, next_review_date, tags, notes,
		     trust_center_public, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7,
		        NULLIF($8, ''), NULLIF($9, ''), NULLIF($10, ''), NULLIF($11, ''),
		        $12, $13, NULLIF($14, ''),
		        $15, $16, $17, NULLIF($18, ''),
		        $19, $20)
		RETURNING id
	`, orgID, in.Name, in.VendorType, crit, status, classArg,
		in.OwnerID, in.Website, in.ContactName, in.ContactEmail, in.Description,
		in.OnboardedDate, in.OffboardedDate, in.AssuranceReport,
		in.LastReviewDate, in.NextReviewDate, tags, in.Notes,
		trustPub, userID).Scan(&id)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"name":        in.Name,
		"vendor_type": in.VendorType,
		"status":      status,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "vendor.created",
		ResourceID:   id.String(),
		ResourceType: "vendor",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	v, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, v)
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
		return echo.NewHTTPError(http.StatusNotFound, "vendor not found")
	}
	if err != nil {
		return err
	}

	var in vendorIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	merged := mergeUpdate(existing, in)
	if _, ok := validVendorTypes[merged.VendorType]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid vendor_type")
	}
	if _, ok := validCriticalities[merged.Criticality]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid criticality")
	}
	if _, ok := validVendorStatuses[merged.Status]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	if merged.DataClassification != nil {
		if _, ok := validClassifications[*merged.DataClassification]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid data_classification")
		}
	}
	if merged.Status == "terminated" && merged.OffboardedDate == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "offboarded_date is required when status is terminated")
	}
	if err := h.validateOwner(c.Request().Context(), orgID, merged.OwnerID); err != nil {
		return err
	}

	_, err = h.pool.Exec(c.Request().Context(), `
		UPDATE vendors
		SET name                = $3,
		    vendor_type         = $4,
		    criticality         = $5,
		    status              = $6,
		    data_classification = $7,
		    owner_id            = $8,
		    website             = $9,
		    contact_name        = $10,
		    contact_email       = $11,
		    description         = $12,
		    onboarded_date      = $13,
		    offboarded_date     = $14,
		    assurance_report    = $15,
		    last_review_date    = $16,
		    next_review_date    = $17,
		    tags                = $18,
		    notes               = $19,
		    trust_center_public = $20,
		    updated_at          = now()
		WHERE org_id = $1 AND id = $2
	`, orgID, id, merged.Name, merged.VendorType, merged.Criticality, merged.Status,
		merged.DataClassification, merged.OwnerID, merged.Website, merged.ContactName,
		merged.ContactEmail, merged.Description, merged.OnboardedDate, merged.OffboardedDate,
		merged.AssuranceReport, merged.LastReviewDate, merged.NextReviewDate,
		merged.Tags, merged.Notes, merged.TrustCenterPublic)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"name":   merged.Name,
		"status": merged.Status,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "vendor.updated",
		ResourceID:   id.String(),
		ResourceType: "vendor",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	v, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, v)
}

func (h *Handler) Delete(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	tag, err := h.pool.Exec(c.Request().Context(),
		`DELETE FROM vendors WHERE org_id = $1 AND id = $2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "vendor not found")
	}

	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "vendor.deleted",
		ResourceID:   id.String(),
		ResourceType: "vendor",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
	})
	return c.NoContent(http.StatusNoContent)
}

// validateEnums normalizes optional enum fields and applies defaults
// (criticality=medium, status=active). Returns the resolved values
// so the caller writes the row from a single source of truth.
func validateEnums(in vendorIn) (string, string, error) {
	if _, ok := validVendorTypes[in.VendorType]; !ok {
		return "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid vendor_type")
	}
	if in.DataClassification != "" {
		if _, ok := validClassifications[in.DataClassification]; !ok {
			return "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid data_classification")
		}
	}
	crit := in.Criticality
	if crit == "" {
		crit = "medium"
	}
	if _, ok := validCriticalities[crit]; !ok {
		return "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid criticality")
	}
	status := in.Status
	if status == "" {
		status = "active"
	}
	if _, ok := validVendorStatuses[status]; !ok {
		return "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	return crit, status, nil
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

func (h *Handler) getByID(ctx context.Context, orgID, id uuid.UUID) (vendorOut, error) {
	row := h.pool.QueryRow(ctx, baseSelect+` WHERE v.org_id = $1 AND v.id = $2`, orgID, id)
	return scanOne(row)
}

type singleRow interface {
	Scan(dest ...any) error
}

func scanOne(r singleRow) (vendorOut, error) {
	var v vendorOut
	err := r.Scan(
		&v.ID, &v.Name, &v.VendorType, &v.Criticality, &v.Status,
		&v.DataClassification, &v.OwnerID, &v.OwnerName,
		&v.Website, &v.ContactName, &v.ContactEmail, &v.Description,
		&v.OnboardedDate, &v.OffboardedDate, &v.AssuranceReport,
		&v.LastReviewDate, &v.NextReviewDate, &v.Tags, &v.Notes,
		&v.TrustCenterPublic,
		&v.CreatedAt, &v.UpdatedAt,
	)
	if v.Tags == nil {
		v.Tags = []string{}
	}
	return v, err
}

// mergeUpdate behaves the same way the personnel / assets variants do:
// empty strings on `in` mean "no change"; explicit values override
// `existing`. data_classification accepts a "none" sentinel so the
// caller can clear a previously set value (empty string is ambiguous
// with "do not change" for nullable enums). Split into three helpers
// so each section stays under the cyclomatic budget.
func mergeUpdate(existing vendorOut, in vendorIn) vendorOut {
	out := existing
	mergeEnumFields(&out, in)
	mergeContactFields(&out, in)
	mergeDateAndCollectionFields(&out, in)
	return out
}

func mergeEnumFields(out *vendorOut, in vendorIn) {
	if in.Name != "" {
		out.Name = strings.TrimSpace(in.Name)
	}
	if in.VendorType != "" {
		out.VendorType = in.VendorType
	}
	if in.Criticality != "" {
		out.Criticality = in.Criticality
	}
	if in.Status != "" {
		out.Status = in.Status
	}
	switch in.DataClassification {
	case "":
		// no change
	case "none":
		out.DataClassification = nil
	default:
		c := in.DataClassification
		out.DataClassification = &c
	}
	if in.OwnerID != nil {
		out.OwnerID = in.OwnerID
	}
}

func mergeContactFields(out *vendorOut, in vendorIn) {
	if in.Website != "" {
		w := in.Website
		out.Website = &w
	}
	if in.ContactName != "" {
		n := in.ContactName
		out.ContactName = &n
	}
	if in.ContactEmail != "" {
		e := in.ContactEmail
		out.ContactEmail = &e
	}
	if in.Description != "" {
		d := in.Description
		out.Description = &d
	}
}

func mergeDateAndCollectionFields(out *vendorOut, in vendorIn) {
	if in.OnboardedDate != nil {
		out.OnboardedDate = in.OnboardedDate
	}
	if in.OffboardedDate != nil {
		out.OffboardedDate = in.OffboardedDate
	}
	if in.AssuranceReport != "" {
		r := in.AssuranceReport
		out.AssuranceReport = &r
	}
	if in.LastReviewDate != nil {
		out.LastReviewDate = in.LastReviewDate
	}
	if in.NextReviewDate != nil {
		out.NextReviewDate = in.NextReviewDate
	}
	if in.Tags != nil {
		out.Tags = normalizeTags(in.Tags)
	}
	if in.Notes != "" {
		n := in.Notes
		out.Notes = &n
	}
	if in.TrustCenterPublic != nil {
		out.TrustCenterPublic = *in.TrustCenterPublic
	}
}

// normalizeTags is the same shape used by the assets package — trims
// whitespace, lower-cases, drops empties, dedups, stable order.
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
