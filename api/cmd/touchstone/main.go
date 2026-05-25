package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ponack/touchstone/internal/config"
	"github.com/ponack/touchstone/internal/db"
	"github.com/ponack/touchstone/internal/server"
	"github.com/ponack/touchstone/internal/worker"
)

func main() {
	root := &cobra.Command{
		Use:   "touchstone",
		Short: "Touchstone — self-hosted compliance evidence collector",
	}

	root.AddCommand(serveCmd(), workerCmd(), migrateCmd(), healthCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the HTTP API server (runs pending migrations on startup)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			slog.Info("running migrations")
			if err := db.Migrate(cfg.Postgres.DSN(), false); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}

			pool, err := db.Open(ctx, cfg)
			if err != nil {
				return err
			}
			defer pool.Close()

			slog.Info("starting API", "addr", ":8080")
			return server.Run(ctx, cfg, pool)
		},
	}
}

func workerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "worker",
		Short: "Run the background job worker (River)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			pool, err := db.Open(ctx, cfg)
			if err != nil {
				return err
			}
			defer pool.Close()

			d, err := worker.New(pool)
			if err != nil {
				return err
			}
			return d.Start(ctx)
		},
	}
}

func migrateCmd() *cobra.Command {
	var down bool
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending database migrations (or step one down with --down)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			return db.Migrate(cfg.Postgres.DSN(), down)
		},
	}
	cmd.Flags().BoolVar(&down, "down", false, "step one migration down instead of running up")
	return cmd
}

func healthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Probe the local API /healthz endpoint (used by Docker healthcheck)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Get("http://127.0.0.1:8080/healthz")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unhealthy: status %d", resp.StatusCode)
			}
			return nil
		},
	}
}
