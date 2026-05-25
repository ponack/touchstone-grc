package connectors

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
	"github.com/ponack/touchstone/internal/secretbox"
)

type Handler struct {
	pool      *pgxpool.Pool
	registry  *Registry
	secretKey string
}

func NewHandler(pool *pgxpool.Pool, registry *Registry, secretKey string) *Handler {
	return &Handler{pool: pool, registry: registry, secretKey: secretKey}
}

// Register attaches connector routes to a protected (authenticated) group.
func (h *Handler) Register(g *echo.Group) {
	g.GET("/connectors/kinds", h.Kinds)
	g.GET("/connectors", h.List)
	g.POST("/connectors", h.Create)
	g.GET("/connectors/:id", h.Get)
	g.PATCH("/connectors/:id", h.Update)
	g.DELETE("/connectors/:id", h.Delete)
}

// Kinds advertises which connector kinds the server knows about.
func (h *Handler) Kinds(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{"kinds": h.registry.Kinds()})
}

type connectorOut struct {
	ID           uuid.UUID       `json:"id"`
	Kind         Kind            `json:"kind"`
	Name         string          `json:"name"`
	Config       json.RawMessage `json:"config"`
	ScheduleCron *string         `json:"schedule_cron,omitempty"`
	IsDisabled   bool            `json:"is_disabled"`
	LastScanAt   *time.Time      `json:"last_scan_at,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

func (h *Handler) List(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	rows, err := h.pool.Query(c.Request().Context(), `
		SELECT id, kind, name, config, schedule_cron, is_disabled, last_scan_at, created_at, updated_at
		FROM connectors
		WHERE org_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []connectorOut{}
	for rows.Next() {
		var co connectorOut
		if err := rows.Scan(&co.ID, &co.Kind, &co.Name, &co.Config, &co.ScheduleCron, &co.IsDisabled, &co.LastScanAt, &co.CreatedAt, &co.UpdatedAt); err != nil {
			return err
		}
		out = append(out, co)
	}
	return c.JSON(http.StatusOK, map[string]any{"connectors": out})
}

func (h *Handler) Get(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	co, err := h.getByID(c.Request().Context(), orgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "connector not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, co)
}

type createIn struct {
	Kind         Kind            `json:"kind"`
	Name         string          `json:"name"`
	Config       json.RawMessage `json:"config"`
	ScheduleCron *string         `json:"schedule_cron,omitempty"`
}

func (h *Handler) Create(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)

	var in createIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if in.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}

	cfg, secret, err := h.validateConfig(in.Kind, in.Config)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	secretsRef, err := h.sealSecret(secret)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to seal secret")
	}

	var id uuid.UUID
	err = h.pool.QueryRow(c.Request().Context(), `
		INSERT INTO connectors (org_id, kind, name, config, secrets_ref, schedule_cron, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`, orgID, in.Kind, in.Name, cfg, nullableText(secretsRef), in.ScheduleCron, userID).Scan(&id)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{"kind": in.Kind, "name": in.Name})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "connector.created",
		ResourceID:   id.String(),
		ResourceType: "connector",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	co, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, co)
}

type updateIn struct {
	Name         *string         `json:"name,omitempty"`
	Config       json.RawMessage `json:"config,omitempty"`
	ScheduleCron *string         `json:"schedule_cron,omitempty"`
	IsDisabled   *bool           `json:"is_disabled,omitempty"`
}

func (h *Handler) Update(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	var existingKind Kind
	if err := h.pool.QueryRow(c.Request().Context(),
		`SELECT kind FROM connectors WHERE org_id = $1 AND id = $2`, orgID, id,
	).Scan(&existingKind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "connector not found")
		}
		return err
	}

	var in updateIn
	if err := c.Bind(&in); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	if err := h.applyUpdate(c.Request().Context(), existingKind, id, in); err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{"kind": existingKind})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "connector.updated",
		ResourceID:   id.String(),
		ResourceType: "connector",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	co, err := h.getByID(c.Request().Context(), orgID, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, co)
}

func (h *Handler) Delete(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	tag, err := h.pool.Exec(c.Request().Context(),
		`DELETE FROM connectors WHERE org_id = $1 AND id = $2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "connector not found")
	}

	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "connector.deleted",
		ResourceID:   id.String(),
		ResourceType: "connector",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
	})

	return c.NoContent(http.StatusNoContent)
}

// applyUpdate runs the Update mutations in one transaction. Split out
// from the handler to keep the request-level method below the
// cyclomatic complexity limit.
func (h *Handler) applyUpdate(ctx context.Context, kind Kind, id uuid.UUID, in updateIn) error {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	type setter struct {
		sql string
		arg any
	}
	var sets []setter
	if in.Name != nil {
		sets = append(sets, setter{`UPDATE connectors SET name = $1, updated_at = now() WHERE id = $2`, *in.Name})
	}
	if in.ScheduleCron != nil {
		sets = append(sets, setter{`UPDATE connectors SET schedule_cron = $1, updated_at = now() WHERE id = $2`, *in.ScheduleCron})
	}
	if in.IsDisabled != nil {
		sets = append(sets, setter{`UPDATE connectors SET is_disabled = $1, updated_at = now() WHERE id = $2`, *in.IsDisabled})
	}
	for _, s := range sets {
		if _, err := tx.Exec(ctx, s.sql, s.arg, id); err != nil {
			return err
		}
	}

	if len(in.Config) > 0 {
		if err := h.applyConfigUpdate(ctx, tx, kind, id, in.Config); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// applyConfigUpdate re-validates incoming config and rewrites the
// secrets_ref only when fresh credentials are supplied.
func (h *Handler) applyConfigUpdate(ctx context.Context, tx pgx.Tx, kind Kind, id uuid.UUID, raw json.RawMessage) error {
	cfg, secret, err := h.validateConfig(kind, raw)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	secretsRef, err := h.sealSecret(secret)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to seal secret")
	}
	if secret != nil {
		_, err = tx.Exec(ctx,
			`UPDATE connectors SET config = $1, secrets_ref = $2, updated_at = now() WHERE id = $3`,
			cfg, secretsRef, id)
		return err
	}
	_, err = tx.Exec(ctx,
		`UPDATE connectors SET config = $1, updated_at = now() WHERE id = $2`,
		cfg, id)
	return err
}

func (h *Handler) getByID(ctx context.Context, orgID, id uuid.UUID) (connectorOut, error) {
	var co connectorOut
	err := h.pool.QueryRow(ctx, `
		SELECT id, kind, name, config, schedule_cron, is_disabled, last_scan_at, created_at, updated_at
		FROM connectors
		WHERE org_id = $1 AND id = $2
	`, orgID, id).Scan(&co.ID, &co.Kind, &co.Name, &co.Config, &co.ScheduleCron, &co.IsDisabled, &co.LastScanAt, &co.CreatedAt, &co.UpdatedAt)
	return co, err
}

// validateConfig looks up the connector implementation by kind and
// delegates to its Validate method.
func (h *Handler) validateConfig(kind Kind, raw json.RawMessage) (cfg, secret json.RawMessage, err error) {
	if len(raw) == 0 {
		return nil, nil, errors.New("config is required")
	}
	conn, ok := h.registry.Get(kind)
	if !ok {
		return nil, nil, errors.New("unknown connector kind: " + string(kind))
	}
	return conn.Validate(raw)
}

func (h *Handler) sealSecret(secret json.RawMessage) (string, error) {
	if secret == nil {
		return "", nil
	}
	return secretbox.Seal([]byte(h.secretKey), secret)
}

// nullableText turns "" into a real NULL on insert/update so the
// secrets_ref column stays clean when a connector kind has no secret.
func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}
