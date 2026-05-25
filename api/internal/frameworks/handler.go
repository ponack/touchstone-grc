package frameworks

import (
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

// Register attaches framework + org-enablement routes to a protected group.
func (h *Handler) Register(g *echo.Group) {
	g.GET("/frameworks", h.List)
	g.GET("/frameworks/:code", h.Get)
	g.GET("/orgs/me/frameworks", h.ListOrgFrameworks)
	g.POST("/orgs/me/frameworks/:code", h.EnableForOrg)
	g.DELETE("/orgs/me/frameworks/:code", h.DisableForOrg)
}

type frameworkOut struct {
	ID       uuid.UUID    `json:"id"`
	Code     string       `json:"code"`
	Name     string       `json:"name"`
	Version  *string      `json:"version,omitempty"`
	Controls []controlOut `json:"controls,omitempty"`
}

type controlOut struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Title       string    `json:"title"`
	Description *string   `json:"description,omitempty"`
	Severity    string    `json:"severity"`
	PolicyPath  string    `json:"policy_path"`
}

func (h *Handler) List(c echo.Context) error {
	rows, err := h.pool.Query(c.Request().Context(),
		`SELECT id, code, name, version FROM frameworks ORDER BY code`)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []frameworkOut{}
	for rows.Next() {
		var fw frameworkOut
		if err := rows.Scan(&fw.ID, &fw.Code, &fw.Name, &fw.Version); err != nil {
			return err
		}
		out = append(out, fw)
	}
	return c.JSON(http.StatusOK, map[string]any{"frameworks": out})
}

func (h *Handler) Get(c echo.Context) error {
	code := c.Param("code")

	var fw frameworkOut
	err := h.pool.QueryRow(c.Request().Context(),
		`SELECT id, code, name, version FROM frameworks WHERE code = $1`, code,
	).Scan(&fw.ID, &fw.Code, &fw.Name, &fw.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "framework not found")
	}
	if err != nil {
		return err
	}

	crows, err := h.pool.Query(c.Request().Context(), `
		SELECT id, code, title, description, severity, policy_path
		FROM controls
		WHERE framework_id = $1
		ORDER BY code
	`, fw.ID)
	if err != nil {
		return err
	}
	defer crows.Close()

	for crows.Next() {
		var co controlOut
		if err := crows.Scan(&co.ID, &co.Code, &co.Title, &co.Description, &co.Severity, &co.PolicyPath); err != nil {
			return err
		}
		fw.Controls = append(fw.Controls, co)
	}
	return c.JSON(http.StatusOK, fw)
}

type orgFrameworkOut struct {
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	EnabledAt time.Time `json:"enabled_at"`
}

func (h *Handler) ListOrgFrameworks(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	rows, err := h.pool.Query(c.Request().Context(), `
		SELECT f.code, f.name, ofw.enabled_at
		FROM org_frameworks ofw
		JOIN frameworks f ON f.id = ofw.framework_id
		WHERE ofw.org_id = $1
		ORDER BY ofw.enabled_at
	`, orgID)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []orgFrameworkOut{}
	for rows.Next() {
		var ofw orgFrameworkOut
		if err := rows.Scan(&ofw.Code, &ofw.Name, &ofw.EnabledAt); err != nil {
			return err
		}
		out = append(out, ofw)
	}
	return c.JSON(http.StatusOK, map[string]any{"frameworks": out})
}

func (h *Handler) EnableForOrg(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	code := c.Param("code")

	var fwID uuid.UUID
	err := h.pool.QueryRow(c.Request().Context(),
		`SELECT id FROM frameworks WHERE code = $1`, code,
	).Scan(&fwID)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "framework not found")
	}
	if err != nil {
		return err
	}

	if _, err := h.pool.Exec(c.Request().Context(), `
		INSERT INTO org_frameworks (org_id, framework_id, enabled_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id, framework_id) DO NOTHING
	`, orgID, fwID, userID); err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]string{"framework": code})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "framework.enabled",
		ResourceID:   fwID.String(),
		ResourceType: "framework",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) DisableForOrg(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	code := c.Param("code")

	var fwID uuid.UUID
	err := h.pool.QueryRow(c.Request().Context(),
		`SELECT id FROM frameworks WHERE code = $1`, code,
	).Scan(&fwID)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "framework not found")
	}
	if err != nil {
		return err
	}

	tag, err := h.pool.Exec(c.Request().Context(),
		`DELETE FROM org_frameworks WHERE org_id = $1 AND framework_id = $2`,
		orgID, fwID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "framework not enabled for this org")
	}

	ctxJSON, _ := json.Marshal(map[string]string{"framework": code})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "framework.disabled",
		ResourceID:   fwID.String(),
		ResourceType: "framework",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	return c.NoContent(http.StatusNoContent)
}
