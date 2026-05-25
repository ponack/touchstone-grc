package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ponack/touchstone/internal/config"
	"github.com/ponack/touchstone/internal/db"
	"github.com/ponack/touchstone/internal/server"
)

func main() {
	root := &cobra.Command{
		Use:   "touchstone",
		Short: "Touchstone — self-hosted compliance evidence collector",
	}

	root.AddCommand(serveCmd(), workerCmd(), healthCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the HTTP API server",
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

			return server.Run(ctx, cfg, pool)
		},
	}
}

func workerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "worker",
		Short: "Run the background job worker (River)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Phase 0 stub. Wire River workers in Phase 1 when first
			// connector scan job lands.
			return fmt.Errorf("worker not yet implemented")
		},
	}
}

func healthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Probe the API health endpoint (used by Docker healthcheck)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Phase 0 stub. Real probe added with the HTTP server.
			return nil
		},
	}
}
