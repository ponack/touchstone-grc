package server

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/ponack/touchstone/internal/config"
)

// Run starts the Echo HTTP server and blocks until ctx is cancelled.
// Phase 0: only /healthz is wired. Auth, RBAC, and the v1 API land in Phase 1.
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

	go func() {
		<-ctx.Done()
		_ = e.Shutdown(context.Background())
	}()

	return e.Start(":8080")
}
