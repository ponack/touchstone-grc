// Package risks exposes the risk register over HTTP.
//
// Captures identified information-security risks the audited
// boundary carries. Maps to SOC 2 CC3.1 + CC3.2 / ISO/IEC 27001:2022
// clause 6.1.2 + A.5.7.
//
// Each row records the inherent L×I rating, the residual L×I after
// the treatment plan, the chosen treatment strategy, the risk owner
// (from the personnel register), and optional attachment to a single
// asset or vendor as the source of the risk.
//
// Auditor-role members see the register read-only; admin / member
// roles can create, update, delete. Every write emits an audit row.
package risks

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
	g.GET("/risks", h.List, auth.RequireOrgRole(h.pool))
	g.GET("/risks/:id", h.Get, auth.RequireOrgRole(h.pool))
	g.POST("/risks", h.Create, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.PATCH("/risks/:id", h.Update, auth.RequireOrgRole(h.pool, "admin", "member"))
	g.DELETE("/risks/:id", h.Delete, auth.RequireOrgRole(h.pool, "admin", "member"))
}

type riskOut struct {
	ID                 uuid.UUID  `json:"id"`
	Title              string     `json:"title"`
	Description        *string    `json:"description,omitempty"`
	RiskCategory       string     `json:"risk_category"`
	InherentLikelihood string     `json:"inherent_likelihood"`
	InherentImpact     string     `json:"inherent_impact"`
	ResidualLikelihood string     `json:"residual_likelihood"`
	ResidualImpact     string     `json:"residual_impact"`
	TreatmentStrategy  string     `json:"treatment_strategy"`
	TreatmentPlan      *string    `json:"treatment_plan,omitempty"`
	Status             string     `json:"status"`
	OwnerID            *uuid.UUID `json:"owner_id,omitempty"`
	OwnerName          *string    `json:"owner_name,omitempty"`
	RelatedAssetID     *uuid.UUID `json:"related_asset_id,omitempty"`
	RelatedAssetName   *string    `json:"related_asset_name,omitempty"`
	RelatedVendorID    *uuid.UUID `json:"related_vendor_id,omitempty"`
	RelatedVendorName  *string    `json:"related_vendor_name,omitempty"`
	IdentifiedDate     time.Time  `json:"identified_date"`
	LastReviewDate     *time.Time `json:"last_review_date,omitempty"`
	NextReviewDate     *time.Time `json:"next_review_date,omitempty"`
	ClosedDate         *time.Time `json:"closed_date,omitempty"`
	Tags               []string   `json:"tags"`
	Notes              *string    `json:"notes,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type riskIn struct {
	Title              string     `json:"title"`
	Description        string     `json:"description,omitempty"`
	RiskCategory       string     `json:"risk_category,omitempty"`
	InherentLikelihood string     `json:"inherent_likelihood,omitempty"`
	InherentImpact     string     `json:"inherent_impact,omitempty"`
	ResidualLikelihood string     `json:"residual_likelihood,omitempty"`
	ResidualImpact     string     `json:"residual_impact,omitempty"`
	TreatmentStrategy  string     `json:"treatment_strategy,omitempty"`
	TreatmentPlan      string     `json:"treatment_plan,omitempty"`
	Status             string     `json:"status,omitempty"`
	OwnerID            *uuid.UUID `json:"owner_id,omitempty"`
	RelatedAssetID     *uuid.UUID `json:"related_asset_id,omitempty"`
	RelatedVendorID    *uuid.UUID `json:"related_vendor_id,omitempty"`
	IdentifiedDate     *time.Time `json:"identified_date,omitempty"`
	LastReviewDate     *time.Time `json:"last_review_date,omitempty"`
	NextReviewDate     *time.Time `json:"next_review_date,omitempty"`
	ClosedDate         *time.Time `json:"closed_date,omitempty"`
	Tags               []string   `json:"tags,omitempty"`
	Notes              string     `json:"notes,omitempty"`
}

var validCategories = map[string]struct{}{
	"operational":  {},
	"security":     {},
	"privacy":      {},
	"compliance":   {},
	"financial":    {},
	"reputational": {},
	"strategic":    {},
	"third_party":  {},
	"other":        {},
}

var validLevels = map[string]struct{}{
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

var validTreatments = map[string]struct{}{
	"accept":   {},
	"mitigate": {},
	"transfer": {},
	"avoid":    {},
}

var validStatuses = map[string]struct{}{
	"identified": {},
	"treating":   {},
	"accepted":   {},
	"closed":     {},
}

const baseSelect = `
	SELECT r.id, r.title, r.description, r.risk_category,
	       r.inherent_likelihood, r.inherent_impact,
	       r.residual_likelihood, r.residual_impact,
	       r.treatment_strategy, r.treatment_plan, r.status,
	       r.owner_id, p.full_name AS owner_name,
	       r.related_asset_id, a.name AS related_asset_name,
	       r.related_vendor_id, v.name AS related_vendor_name,
	       r.identified_date, r.last_review_date, r.next_review_date,
	       r.closed_date, r.tags, r.notes,
	       r.created_at, r.updated_at
	FROM risks r
	LEFT JOIN personnel p ON p.id = r.owner_id
	LEFT JOIN assets    a ON a.id = r.related_asset_id
	LEFT JOIN vendors   v ON v.id = r.related_vendor_id
`

func (h *Handler) List(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)

	args := []any{orgID}
	sql := baseSelect + ` WHERE r.org_id = $1`
	if cat := c.QueryParam("category"); cat != "" {
		if _, ok := validCategories[cat]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid category filter")
		}
		args = append(args, cat)
		sql += fmt.Sprintf(` AND r.risk_category = $%d`, len(args))
	}
	if s := c.QueryParam("status"); s != "" {
		if _, ok := validStatuses[s]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid status filter")
		}
		args = append(args, s)
		sql += fmt.Sprintf(` AND r.status = $%d`, len(args))
	}
	if r := c.QueryParam("review_due"); r == "true" {
		sql += ` AND (r.next_review_date IS NULL OR r.next_review_date <= CURRENT_DATE)`
	}
	sql += ` ORDER BY r.identified_date DESC, r.title ASC`

	rows, err := h.pool.Query(c.Request().Context(), sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []riskOut{}
	for rows.Next() {
		r, err := scanOne(rows)
		if err != nil {
			return err
		}
		out = append(out, r)
	}
	return c.JSON(http.StatusOK, map[string]any{"risks": out})
}

func (h *Handler) Get(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	r, err := h.getByID(c.Request().Context(), orgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "risk not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, r)
}

func (h *Handler) Create(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)

	var in riskIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	in.Title = strings.TrimSpace(in.Title)
	if in.Title == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "title is required")
	}
	cat, ilL, ilI, rlL, rlI, treat, status, err := validateEnums(in)
	if err != nil {
		return err
	}
	if status == "closed" && in.ClosedDate == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "closed_date is required when status is closed")
	}
	if err := h.validateReferences(c.Request().Context(), orgID, in.OwnerID, in.RelatedAssetID, in.RelatedVendorID); err != nil {
		return err
	}
	tags := normalizeTags(in.Tags)
	identified := time.Now().UTC()
	if in.IdentifiedDate != nil {
		identified = *in.IdentifiedDate
	}

	var id uuid.UUID
	err = h.pool.QueryRow(c.Request().Context(), `
		INSERT INTO risks
		    (org_id, title, description, risk_category,
		     inherent_likelihood, inherent_impact,
		     residual_likelihood, residual_impact,
		     treatment_strategy, treatment_plan, status,
		     owner_id, related_asset_id, related_vendor_id,
		     identified_date, last_review_date, next_review_date, closed_date,
		     tags, notes, created_by)
		VALUES ($1, $2, NULLIF($3, ''), $4,
		        $5, $6, $7, $8,
		        $9, NULLIF($10, ''), $11,
		        $12, $13, $14,
		        $15, $16, $17, $18,
		        $19, NULLIF($20, ''), $21)
		RETURNING id
	`, orgID, in.Title, in.Description, cat,
		ilL, ilI, rlL, rlI,
		treat, in.TreatmentPlan, status,
		in.OwnerID, in.RelatedAssetID, in.RelatedVendorID,
		identified, in.LastReviewDate, in.NextReviewDate, in.ClosedDate,
		tags, in.Notes, userID).Scan(&id)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"title":    in.Title,
		"category": cat,
		"status":   status,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "risk.created",
		ResourceID:   id.String(),
		ResourceType: "risk",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	r, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, r)
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
		return echo.NewHTTPError(http.StatusNotFound, "risk not found")
	}
	if err != nil {
		return err
	}

	var in riskIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	merged := mergeUpdate(existing, in)
	if err := validateMerged(&merged); err != nil {
		return err
	}
	if err := h.validateReferences(c.Request().Context(), orgID, merged.OwnerID, merged.RelatedAssetID, merged.RelatedVendorID); err != nil {
		return err
	}

	_, err = h.pool.Exec(c.Request().Context(), `
		UPDATE risks
		SET title               = $3,
		    description         = $4,
		    risk_category       = $5,
		    inherent_likelihood = $6,
		    inherent_impact     = $7,
		    residual_likelihood = $8,
		    residual_impact     = $9,
		    treatment_strategy  = $10,
		    treatment_plan      = $11,
		    status              = $12,
		    owner_id            = $13,
		    related_asset_id    = $14,
		    related_vendor_id   = $15,
		    identified_date     = $16,
		    last_review_date    = $17,
		    next_review_date    = $18,
		    closed_date         = $19,
		    tags                = $20,
		    notes               = $21,
		    updated_at          = now()
		WHERE org_id = $1 AND id = $2
	`, orgID, id, merged.Title, merged.Description, merged.RiskCategory,
		merged.InherentLikelihood, merged.InherentImpact,
		merged.ResidualLikelihood, merged.ResidualImpact,
		merged.TreatmentStrategy, merged.TreatmentPlan, merged.Status,
		merged.OwnerID, merged.RelatedAssetID, merged.RelatedVendorID,
		merged.IdentifiedDate, merged.LastReviewDate, merged.NextReviewDate, merged.ClosedDate,
		merged.Tags, merged.Notes)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"title":  merged.Title,
		"status": merged.Status,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "risk.updated",
		ResourceID:   id.String(),
		ResourceType: "risk",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	r, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, r)
}

func (h *Handler) Delete(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	tag, err := h.pool.Exec(c.Request().Context(),
		`DELETE FROM risks WHERE org_id = $1 AND id = $2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "risk not found")
	}

	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "risk.deleted",
		ResourceID:   id.String(),
		ResourceType: "risk",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
	})
	return c.NoContent(http.StatusNoContent)
}

// validateEnums normalizes enum-or-default fields on create and
// returns the resolved values so the caller writes the row from a
// single source of truth.
func validateEnums(in riskIn) (string, string, string, string, string, string, string, error) {
	cat := in.RiskCategory
	if cat == "" {
		cat = "security"
	}
	if _, ok := validCategories[cat]; !ok {
		return "", "", "", "", "", "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid risk_category")
	}
	ilL := defaultLevel(in.InherentLikelihood)
	ilI := defaultLevel(in.InherentImpact)
	rlL := defaultLevel(in.ResidualLikelihood)
	rlI := defaultLevel(in.ResidualImpact)
	if !levelOK(ilL) || !levelOK(ilI) || !levelOK(rlL) || !levelOK(rlI) {
		return "", "", "", "", "", "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid likelihood / impact level")
	}
	treat := in.TreatmentStrategy
	if treat == "" {
		treat = "mitigate"
	}
	if _, ok := validTreatments[treat]; !ok {
		return "", "", "", "", "", "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid treatment_strategy")
	}
	status := in.Status
	if status == "" {
		status = "identified"
	}
	if _, ok := validStatuses[status]; !ok {
		return "", "", "", "", "", "", "", echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	return cat, ilL, ilI, rlL, rlI, treat, status, nil
}

// validateMerged checks every enum + cross-field invariant on the
// merged PATCH payload. Extracted from Update() to stay below the
// cyclomatic budget.
func validateMerged(merged *riskOut) error {
	if _, ok := validCategories[merged.RiskCategory]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid risk_category")
	}
	if !levelOK(merged.InherentLikelihood) || !levelOK(merged.InherentImpact) ||
		!levelOK(merged.ResidualLikelihood) || !levelOK(merged.ResidualImpact) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid likelihood / impact level")
	}
	if _, ok := validTreatments[merged.TreatmentStrategy]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid treatment_strategy")
	}
	if _, ok := validStatuses[merged.Status]; !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	if merged.Status == "closed" && merged.ClosedDate == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "closed_date is required when status is closed")
	}
	return nil
}

func defaultLevel(s string) string {
	if s == "" {
		return "medium"
	}
	return s
}

func levelOK(s string) bool {
	_, ok := validLevels[s]
	return ok
}

func (h *Handler) validateReferences(ctx context.Context, orgID uuid.UUID, ownerID, assetID, vendorID *uuid.UUID) error {
	if ownerID != nil {
		var ok bool
		if err := h.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM personnel WHERE id = $1 AND org_id = $2)`,
			*ownerID, orgID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "owner_id does not reference a person in this org")
		}
	}
	if assetID != nil {
		var ok bool
		if err := h.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM assets WHERE id = $1 AND org_id = $2)`,
			*assetID, orgID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "related_asset_id does not reference an asset in this org")
		}
	}
	if vendorID != nil {
		var ok bool
		if err := h.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM vendors WHERE id = $1 AND org_id = $2)`,
			*vendorID, orgID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "related_vendor_id does not reference a vendor in this org")
		}
	}
	return nil
}

func (h *Handler) getByID(ctx context.Context, orgID, id uuid.UUID) (riskOut, error) {
	row := h.pool.QueryRow(ctx, baseSelect+` WHERE r.org_id = $1 AND r.id = $2`, orgID, id)
	return scanOne(row)
}

type singleRow interface {
	Scan(dest ...any) error
}

func scanOne(r singleRow) (riskOut, error) {
	var o riskOut
	err := r.Scan(
		&o.ID, &o.Title, &o.Description, &o.RiskCategory,
		&o.InherentLikelihood, &o.InherentImpact,
		&o.ResidualLikelihood, &o.ResidualImpact,
		&o.TreatmentStrategy, &o.TreatmentPlan, &o.Status,
		&o.OwnerID, &o.OwnerName,
		&o.RelatedAssetID, &o.RelatedAssetName,
		&o.RelatedVendorID, &o.RelatedVendorName,
		&o.IdentifiedDate, &o.LastReviewDate, &o.NextReviewDate,
		&o.ClosedDate, &o.Tags, &o.Notes,
		&o.CreatedAt, &o.UpdatedAt,
	)
	if o.Tags == nil {
		o.Tags = []string{}
	}
	return o, err
}

// mergeUpdate behaves the same way the other GRC handlers do:
// empty strings on `in` mean "no change"; explicit values override
// `existing`. Split across helpers to keep cyclomatic complexity
// in line.
func mergeUpdate(existing riskOut, in riskIn) riskOut {
	out := existing
	mergeIdentity(&out, in)
	mergeLevels(&out, in)
	mergeOwnership(&out, in)
	mergeDates(&out, in)
	mergeTagsAndNotes(&out, in)
	return out
}

func mergeIdentity(out *riskOut, in riskIn) {
	if in.Title != "" {
		out.Title = strings.TrimSpace(in.Title)
	}
	if in.Description != "" {
		d := in.Description
		out.Description = &d
	}
	if in.RiskCategory != "" {
		out.RiskCategory = in.RiskCategory
	}
}

func mergeLevels(out *riskOut, in riskIn) {
	if in.InherentLikelihood != "" {
		out.InherentLikelihood = in.InherentLikelihood
	}
	if in.InherentImpact != "" {
		out.InherentImpact = in.InherentImpact
	}
	if in.ResidualLikelihood != "" {
		out.ResidualLikelihood = in.ResidualLikelihood
	}
	if in.ResidualImpact != "" {
		out.ResidualImpact = in.ResidualImpact
	}
	if in.TreatmentStrategy != "" {
		out.TreatmentStrategy = in.TreatmentStrategy
	}
	if in.TreatmentPlan != "" {
		t := in.TreatmentPlan
		out.TreatmentPlan = &t
	}
	if in.Status != "" {
		out.Status = in.Status
	}
}

func mergeOwnership(out *riskOut, in riskIn) {
	if in.OwnerID != nil {
		out.OwnerID = in.OwnerID
	}
	if in.RelatedAssetID != nil {
		out.RelatedAssetID = in.RelatedAssetID
	}
	if in.RelatedVendorID != nil {
		out.RelatedVendorID = in.RelatedVendorID
	}
}

func mergeDates(out *riskOut, in riskIn) {
	if in.IdentifiedDate != nil {
		out.IdentifiedDate = *in.IdentifiedDate
	}
	if in.LastReviewDate != nil {
		out.LastReviewDate = in.LastReviewDate
	}
	if in.NextReviewDate != nil {
		out.NextReviewDate = in.NextReviewDate
	}
	if in.ClosedDate != nil {
		out.ClosedDate = in.ClosedDate
	}
}

func mergeTagsAndNotes(out *riskOut, in riskIn) {
	if in.Tags != nil {
		out.Tags = normalizeTags(in.Tags)
	}
	if in.Notes != "" {
		n := in.Notes
		out.Notes = &n
	}
}

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
