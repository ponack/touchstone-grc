package scans

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	"github.com/ponack/touchstone/internal/audit"
	"github.com/ponack/touchstone/internal/auth"
	"github.com/ponack/touchstone/internal/queue"
)

type Handler struct {
	pool  *pgxpool.Pool
	queue *queue.Client
}

func NewHandler(pool *pgxpool.Pool, q *queue.Client) *Handler {
	return &Handler{pool: pool, queue: q}
}

func (h *Handler) Register(g *echo.Group) {
	g.GET("/scans", h.List)
	g.POST("/scans", h.Create)
	g.GET("/scans/:id", h.Get)
}

type scanOut struct {
	ID             uuid.UUID  `json:"id"`
	ConnectorID    uuid.UUID  `json:"connector_id"`
	Status         string     `json:"status"`
	Trigger        string     `json:"trigger"`
	TriggeredBy    *uuid.UUID `json:"triggered_by,omitempty"`
	ArtifactKey    *string    `json:"artifact_key,omitempty"`
	ErrorMessage   *string    `json:"error_message,omitempty"`
	ResourcesCount int        `json:"resources_count"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

func (h *Handler) List(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)

	limit := 50
	if v := c.QueryParam("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	args := []any{orgID, limit}
	sql := `
		SELECT id, connector_id, status, trigger, triggered_by, artifact_key,
		       error_message, resources_count, started_at, finished_at, created_at
		FROM scans
		WHERE org_id = $1
	`
	if cid := c.QueryParam("connector_id"); cid != "" {
		parsed, err := uuid.Parse(cid)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid connector_id")
		}
		sql += ` AND connector_id = $3`
		args = append(args, parsed)
	}
	sql += ` ORDER BY created_at DESC LIMIT $2`

	rows, err := h.pool.Query(c.Request().Context(), sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	out := []scanOut{}
	for rows.Next() {
		s, err := scanScanOne(rows)
		if err != nil {
			return err
		}
		out = append(out, s)
	}
	return c.JSON(http.StatusOK, map[string]any{"scans": out})
}

func (h *Handler) Get(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	row := h.pool.QueryRow(c.Request().Context(), `
		SELECT id, connector_id, status, trigger, triggered_by, artifact_key,
		       error_message, resources_count, started_at, finished_at, created_at
		FROM scans
		WHERE org_id = $1 AND id = $2
	`, orgID, id)

	s, err := scanScanOne(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "scan not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, s)
}

type createIn struct {
	ConnectorID uuid.UUID `json:"connector_id"`
}

func (h *Handler) Create(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	userID := c.Get(auth.ContextUserID).(uuid.UUID)

	var in createIn
	if err := c.Bind(&in); err != nil || in.ConnectorID == uuid.Nil {
		return echo.NewHTTPError(http.StatusBadRequest, "connector_id is required")
	}

	// Verify connector belongs to this org + is not disabled before we burn a row.
	var disabled bool
	err := h.pool.QueryRow(c.Request().Context(),
		`SELECT is_disabled FROM connectors WHERE org_id = $1 AND id = $2`,
		orgID, in.ConnectorID).Scan(&disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "connector not found")
	}
	if err != nil {
		return err
	}
	if disabled {
		return echo.NewHTTPError(http.StatusConflict, "connector is disabled")
	}

	scanID, err := h.insertAndEnqueue(c.Request().Context(), orgID, in.ConnectorID, userID)
	if err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]any{"connector_id": in.ConnectorID})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:      &userID,
		Action:       "scan.queued",
		ResourceID:   scanID.String(),
		ResourceType: "scan",
		OrgID:        &orgID,
		IPAddress:    c.RealIP(),
		Context:      ctxJSON,
	})

	s, err := h.getByID(c.Request().Context(), orgID, scanID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusAccepted, s)
}

// insertAndEnqueue inserts the scan row and enqueues the River job
// inside one transaction so we never leak orphan rows when the queue
// insert fails.
func (h *Handler) insertAndEnqueue(ctx context.Context, orgID, connectorID, userID uuid.UUID) (uuid.UUID, error) {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	var scanID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO scans (org_id, connector_id, status, trigger, triggered_by)
		VALUES ($1, $2, 'queued', 'manual', $3)
		RETURNING id
	`, orgID, connectorID, userID).Scan(&scanID); err != nil {
		return uuid.Nil, err
	}

	if err := h.queue.EnqueueScanTx(ctx, tx, scanID); err != nil {
		return uuid.Nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return scanID, nil
}

func (h *Handler) getByID(ctx context.Context, orgID, id uuid.UUID) (scanOut, error) {
	row := h.pool.QueryRow(ctx, `
		SELECT id, connector_id, status, trigger, triggered_by, artifact_key,
		       error_message, resources_count, started_at, finished_at, created_at
		FROM scans
		WHERE org_id = $1 AND id = $2
	`, orgID, id)
	return scanScanOne(row)
}

// scanScanOne is shared by List + Get + insertAndEnqueue follow-up.
// rowOrRows accepts both a Row (single result) and a Rows (iterator).
type singleRow interface {
	Scan(dest ...any) error
}

func scanScanOne(r singleRow) (scanOut, error) {
	var s scanOut
	err := r.Scan(
		&s.ID, &s.ConnectorID, &s.Status, &s.Trigger, &s.TriggeredBy,
		&s.ArtifactKey, &s.ErrorMessage, &s.ResourcesCount,
		&s.StartedAt, &s.FinishedAt, &s.CreatedAt,
	)
	return s, err
}
