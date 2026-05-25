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

	authH := auth.NewHandler(cfg, pool)
	authH.Register(e)

	v1 := e.Group("/api/v1", auth.RequireUser(cfg.SecretKey))
	v1.GET("/me", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{
			"user_id": c.Get(auth.ContextUserID).(uuid.UUID),
			"org_id":  c.Get(auth.ContextOrgID).(uuid.UUID),
			"email":   c.Get(auth.ContextEmail),
			"name":    c.Get(auth.ContextName),
		})
	})

	go func() {
		<-ctx.Done()
		_ = e.Shutdown(context.Background())
	}()

	return e.Start(":8080")
}
