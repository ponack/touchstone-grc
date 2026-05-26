package server

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/ponack/touchstone/internal/auth"
	"github.com/ponack/touchstone/internal/config"
	"github.com/ponack/touchstone/internal/connectors"
	awsconn "github.com/ponack/touchstone/internal/connectors/aws"
	"github.com/ponack/touchstone/internal/evidence"
	"github.com/ponack/touchstone/internal/exceptions"
	"github.com/ponack/touchstone/internal/exports"
	"github.com/ponack/touchstone/internal/frameworks"
	"github.com/ponack/touchstone/internal/queue"
	"github.com/ponack/touchstone/internal/scans"
)

// Run starts the Echo HTTP server and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool) error {
	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.Logger())

	e.GET("/healthz", func(c echo.Context) error {
		if err := pool.Ping(c.Request().Context()); err != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"status": "db_unavailable"})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	if err := frameworks.Load(ctx, pool); err != nil {
		return err
	}

	authH, err := auth.NewHandler(cfg, pool)
	if err != nil {
		return err
	}
	authH.Register(e)

	registry := connectors.NewRegistry()
	registry.Register(awsconn.New())

	v1 := e.Group("/api/v1", auth.RequireUser(cfg.SecretKey))
	v1.GET("/me", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{
			"user_id": c.Get(auth.ContextUserID).(uuid.UUID),
			"org_id":  c.Get(auth.ContextOrgID).(uuid.UUID),
			"email":   c.Get(auth.ContextEmail),
			"name":    c.Get(auth.ContextName),
		})
	})

	q, err := queue.New(pool)
	if err != nil {
		return err
	}

	connectors.NewHandler(pool, registry, cfg.SecretKey).Register(v1)
	frameworks.NewHandler(pool).Register(v1)
	scans.NewHandler(pool, q).Register(v1)
	evidence.NewHandler(pool).Register(v1)
	exceptions.NewHandler(pool).Register(v1)
	exports.NewHandler(pool).Register(v1)

	go func() {
		<-ctx.Done()
		_ = e.Shutdown(context.Background())
	}()

	return e.Start(":8080")
}
