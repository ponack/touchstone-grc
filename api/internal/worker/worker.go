// Package worker owns the River worker pool that processes background
// jobs (scan execution today; scheduled scans, evidence retention, and
// notification fan-out in follow-up PRs). Workers run inside the
// `touchstone worker` process.
package worker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/ponack/touchstone/internal/queue"
)

// Dispatcher binds the worker pool to a database pool and starts
// processing jobs from River's queues.
type Dispatcher struct {
	pool  *pgxpool.Pool
	river *river.Client[pgx.Tx]
}

// New builds the worker dispatcher and registers every job type
// Touchstone knows how to process.
func New(pool *pgxpool.Pool) (*Dispatcher, error) {
	workers := river.NewWorkers()
	river.AddWorker(workers, &ScanWorker{pool: pool})

	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 4},
		},
		Workers: workers,
	})
	if err != nil {
		return nil, fmt.Errorf("river client: %w", err)
	}

	return &Dispatcher{pool: pool, river: rc}, nil
}

// Start begins job processing and blocks until ctx is cancelled, then
// gracefully drains in-flight jobs (30s budget).
func (d *Dispatcher) Start(ctx context.Context) error {
	slog.Info("worker starting", "max_workers", 4)
	if err := d.river.Start(ctx); err != nil {
		return fmt.Errorf("river start: %w", err)
	}
	<-ctx.Done()
	stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	slog.Info("worker stopping")
	return d.river.Stop(stopCtx)
}

// ScanWorker is the stub processor for scan jobs. It moves the scan
// row through queued → running → succeeded with no real work between.
// PR D.2 (AWS SDK) and PR D.3 (OPA evaluator) replace the body.
type ScanWorker struct {
	river.WorkerDefaults[queue.ScanJobArgs]
	pool *pgxpool.Pool
}

func (w *ScanWorker) Work(ctx context.Context, job *river.Job[queue.ScanJobArgs]) error {
	scanID := job.Args.ScanID
	slog.Info("scan job picked up", "scan_id", scanID)

	if _, err := w.pool.Exec(ctx, `
		UPDATE scans
		SET status = 'running', started_at = now()
		WHERE id = $1 AND status = 'queued'
	`, scanID); err != nil {
		return fmt.Errorf("transition to running: %w", err)
	}

	// TODO(PR D.2): AWS resource enumeration via aws-sdk-go-v2.
	// TODO(PR D.3): OPA evaluation populates evidence_items.

	if _, err := w.pool.Exec(ctx, `
		UPDATE scans
		SET status = 'succeeded', finished_at = now(), resources_count = 0
		WHERE id = $1
	`, scanID); err != nil {
		return fmt.Errorf("transition to succeeded: %w", err)
	}

	slog.Info("scan job complete (stub)", "scan_id", scanID)
	return nil
}
