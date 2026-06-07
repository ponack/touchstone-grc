// Package trustcenter exposes the public-facing Trust Center over
// HTTP. Two surfaces:
//
//	/api/v1/trust-center          — admin GET + PATCH (per-org config)
//	/public/trust/:slug           — unauthenticated public read
//
// One trust_centers row per org. The row is auto-created on the
// first admin GET with the org's slug as the default — there's no
// explicit "create" step.
//
// Maps loosely to SOC 2 CC2.3 (external communications) +
// ISO/IEC 27001:2022 A.5.18 (public information).
package trustcenter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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

// RegisterAdmin attaches the per-org admin endpoints under the
// authenticated v1 group. Auditor reads, member/admin can write.
func (h *Handler) RegisterAdmin(g *echo.Group) {
	g.GET("/trust-center", h.GetMine, auth.RequireOrgRole(h.pool))
	g.PATCH("/trust-center", h.Update, auth.RequireOrgRole(h.pool, "admin", "member"))
}

// RegisterPublic attaches the unauthenticated public endpoint on
// the root echo instance. Resolves a slug → org → shaped payload.
func (h *Handler) RegisterPublic(e *echo.Echo) {
	e.GET("/public/trust/:slug", h.Public)
}

type trustCenterOut struct {
	OrgID             uuid.UUID `json:"org_id"`
	OrgSlug           string    `json:"org_slug"`
	Slug              string    `json:"slug"`
	IsPublic          bool      `json:"is_public"`
	DisplayName       *string   `json:"display_name,omitempty"`
	Tagline           *string   `json:"tagline,omitempty"`
	PrimaryColor      *string   `json:"primary_color,omitempty"`
	LogoURL           *string   `json:"logo_url,omitempty"`
	ContactEmail      *string   `json:"contact_email,omitempty"`
	ContactURL        *string   `json:"contact_url,omitempty"`
	ShowFrameworks    bool      `json:"show_frameworks"`
	ShowSubprocessors bool      `json:"show_subprocessors"`
	ShowContact       bool      `json:"show_contact"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type trustCenterIn struct {
	Slug              string `json:"slug,omitempty"`
	IsPublic          *bool  `json:"is_public,omitempty"`
	DisplayName       string `json:"display_name,omitempty"`
	Tagline           string `json:"tagline,omitempty"`
	PrimaryColor      string `json:"primary_color,omitempty"`
	LogoURL           string `json:"logo_url,omitempty"`
	ContactEmail      string `json:"contact_email,omitempty"`
	ContactURL        string `json:"contact_url,omitempty"`
	ShowFrameworks    *bool  `json:"show_frameworks,omitempty"`
	ShowSubprocessors *bool  `json:"show_subprocessors,omitempty"`
	ShowContact       *bool  `json:"show_contact,omitempty"`
}

var slugRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func validSlug(s string) bool {
	if len(s) == 0 || len(s) > 60 {
		return false
	}
	return slugRE.MatchString(s)
}

func (h *Handler) GetMine(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	tc, err := h.getOrCreate(c.Request().Context(), orgID, userID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, tc)
}

func (h *Handler) Update(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)

	var in trustCenterIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if in.Slug != "" && !validSlug(in.Slug) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid slug — must be lowercase kebab-case, 1-60 chars")
	}

	if _, err := h.getOrCreate(c.Request().Context(), orgID, userID); err != nil {
		return err
	}

	sets, args := buildPatch(orgID, in)
	if len(sets) == 0 {
		// Nothing to change; just return the current state.
		tc, err := h.byOrgID(c.Request().Context(), orgID)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, tc)
	}

	sql := "UPDATE trust_centers SET " + strings.Join(sets, ", ") + ", updated_at = now() WHERE org_id = $1"
	tag, err := h.pool.Exec(c.Request().Context(), sql, args...)
	if err != nil {
		if strings.Contains(err.Error(), "trust_centers_slug_key") {
			return echo.NewHTTPError(http.StatusConflict, "slug is already taken by another organization")
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "trust center not found")
	}

	ctxJSON, _ := json.Marshal(map[string]any{
		"slug":      in.Slug,
		"is_public": in.IsPublic,
	})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "trust_center.updated",
		ResourceID:   orgID.String(),
		ResourceType: "trust_center",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	tc, err := h.byOrgID(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, tc)
}

// buildPatch turns the partial PATCH input into a list of SET
// clauses + the args slice. Returns ([]"col = $N"), ([]any{...}).
// $1 is always the org_id WHERE arg.
func buildPatch(orgID uuid.UUID, in trustCenterIn) ([]string, []any) {
	args := []any{orgID}
	sets := []string{}
	addStr := func(col, v string) {
		if v == "" {
			return
		}
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	addBool := func(col string, v *bool) {
		if v == nil {
			return
		}
		args = append(args, *v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	addStr("slug", in.Slug)
	addBool("is_public", in.IsPublic)
	addStr("display_name", in.DisplayName)
	addStr("tagline", in.Tagline)
	addStr("primary_color", in.PrimaryColor)
	addStr("logo_url", in.LogoURL)
	addStr("contact_email", in.ContactEmail)
	addStr("contact_url", in.ContactURL)
	addBool("show_frameworks", in.ShowFrameworks)
	addBool("show_subprocessors", in.ShowSubprocessors)
	addBool("show_contact", in.ShowContact)
	return sets, args
}

// Public is the unauthenticated trust-center read endpoint.
// Resolves slug → org → shaped response with branding +
// (optionally) the enabled framework list + the curated
// subprocessor list. Returns 404 for unknown slugs OR when the
// trust center is not yet public — does NOT distinguish between
// those two cases (avoids leaking which slugs are taken).
func (h *Handler) Public(c echo.Context) error {
	slug := strings.ToLower(strings.TrimSpace(c.Param("slug")))
	if !validSlug(slug) {
		return echo.NewHTTPError(http.StatusNotFound, "not found")
	}

	tc, err := h.bySlug(c.Request().Context(), slug)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !tc.IsPublic) {
		return echo.NewHTTPError(http.StatusNotFound, "not found")
	}
	if err != nil {
		return err
	}

	resp := map[string]any{
		"slug":               tc.Slug,
		"display_name":       displayName(tc),
		"tagline":            tc.Tagline,
		"primary_color":      tc.PrimaryColor,
		"logo_url":           tc.LogoURL,
		"contact_email":      tc.ContactEmail,
		"contact_url":        tc.ContactURL,
		"show_frameworks":    tc.ShowFrameworks,
		"show_subprocessors": tc.ShowSubprocessors,
		"show_contact":       tc.ShowContact,
		"updated_at":         tc.UpdatedAt,
	}

	if tc.ShowFrameworks {
		fws, err := h.publicFrameworks(c.Request().Context(), tc.OrgID)
		if err != nil {
			return err
		}
		resp["frameworks"] = fws
	}
	if tc.ShowSubprocessors {
		subs, err := h.publicSubprocessors(c.Request().Context(), tc.OrgID)
		if err != nil {
			return err
		}
		resp["subprocessors"] = subs
	}

	return c.JSON(http.StatusOK, resp)
}

func displayName(tc trustCenterOut) string {
	if tc.DisplayName != nil && *tc.DisplayName != "" {
		return *tc.DisplayName
	}
	return tc.OrgSlug
}

type publicFramework struct {
	Code    string `json:"code"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type publicSubprocessor struct {
	Name            string  `json:"name"`
	VendorType      string  `json:"vendor_type"`
	AssuranceReport *string `json:"assurance_report,omitempty"`
	Website         *string `json:"website,omitempty"`
}

func (h *Handler) publicFrameworks(ctx context.Context, orgID uuid.UUID) ([]publicFramework, error) {
	rows, err := h.pool.Query(ctx, `
		SELECT f.code, f.name, f.version
		FROM org_frameworks ofw
		JOIN frameworks f ON f.id = ofw.framework_id
		WHERE ofw.org_id = $1
		ORDER BY f.name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []publicFramework{}
	for rows.Next() {
		var f publicFramework
		var v *string
		if err := rows.Scan(&f.Code, &f.Name, &v); err != nil {
			return nil, err
		}
		if v != nil {
			f.Version = *v
		}
		out = append(out, f)
	}
	return out, nil
}

func (h *Handler) publicSubprocessors(ctx context.Context, orgID uuid.UUID) ([]publicSubprocessor, error) {
	rows, err := h.pool.Query(ctx, `
		SELECT name, vendor_type, assurance_report, website
		FROM vendors
		WHERE org_id = $1
		  AND trust_center_public = true
		  AND status = 'active'
		ORDER BY name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []publicSubprocessor{}
	for rows.Next() {
		var s publicSubprocessor
		if err := rows.Scan(&s.Name, &s.VendorType, &s.AssuranceReport, &s.Website); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// getOrCreate idempotently creates the trust_centers row for the
// given org if it doesn't exist yet, then returns it. The default
// slug is the org's slug; the row is created with is_public=false
// so a fresh org never exposes anything until the admin explicitly
// flips the flag.
func (h *Handler) getOrCreate(ctx context.Context, orgID, createdBy uuid.UUID) (trustCenterOut, error) {
	var orgSlug string
	if err := h.pool.QueryRow(ctx,
		`SELECT slug FROM organizations WHERE id = $1`, orgID).Scan(&orgSlug); err != nil {
		return trustCenterOut{}, err
	}
	_, err := h.pool.Exec(ctx, `
		INSERT INTO trust_centers (org_id, slug, created_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id) DO NOTHING
	`, orgID, orgSlug, createdBy)
	if err != nil {
		// Possible: another org already owns this slug (unlikely
		// in single-tenant installs, but the multi-tenant model
		// allows it). Fall back to a slug derived from the
		// org_id's hex prefix so the row exists deterministically.
		if !strings.Contains(err.Error(), "trust_centers_slug_key") {
			return trustCenterOut{}, err
		}
		fallback := orgSlug + "-" + orgID.String()[:8]
		if _, err := h.pool.Exec(ctx, `
			INSERT INTO trust_centers (org_id, slug, created_by)
			VALUES ($1, $2, $3)
			ON CONFLICT (org_id) DO NOTHING
		`, orgID, fallback, createdBy); err != nil {
			return trustCenterOut{}, err
		}
	}
	return h.byOrgID(ctx, orgID)
}

func (h *Handler) byOrgID(ctx context.Context, orgID uuid.UUID) (trustCenterOut, error) {
	row := h.pool.QueryRow(ctx, `
		SELECT t.org_id, o.slug AS org_slug, t.slug, t.is_public,
		       t.display_name, t.tagline, t.primary_color, t.logo_url,
		       t.contact_email, t.contact_url,
		       t.show_frameworks, t.show_subprocessors, t.show_contact,
		       t.updated_at
		FROM trust_centers t
		JOIN organizations o ON o.id = t.org_id
		WHERE t.org_id = $1
	`, orgID)
	return scanOne(row)
}

func (h *Handler) bySlug(ctx context.Context, slug string) (trustCenterOut, error) {
	row := h.pool.QueryRow(ctx, `
		SELECT t.org_id, o.slug AS org_slug, t.slug, t.is_public,
		       t.display_name, t.tagline, t.primary_color, t.logo_url,
		       t.contact_email, t.contact_url,
		       t.show_frameworks, t.show_subprocessors, t.show_contact,
		       t.updated_at
		FROM trust_centers t
		JOIN organizations o ON o.id = t.org_id
		WHERE t.slug = $1
	`, slug)
	return scanOne(row)
}

type singleRow interface {
	Scan(dest ...any) error
}

func scanOne(r singleRow) (trustCenterOut, error) {
	var tc trustCenterOut
	err := r.Scan(
		&tc.OrgID, &tc.OrgSlug, &tc.Slug, &tc.IsPublic,
		&tc.DisplayName, &tc.Tagline, &tc.PrimaryColor, &tc.LogoURL,
		&tc.ContactEmail, &tc.ContactURL,
		&tc.ShowFrameworks, &tc.ShowSubprocessors, &tc.ShowContact,
		&tc.UpdatedAt,
	)
	return tc, err
}
