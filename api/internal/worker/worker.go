// Package worker owns the River worker pool that processes background
// jobs (scan execution today; scheduled scans, evidence retention, and
// notification fan-out in follow-up PRs). Workers run inside the
// `touchstone worker` process.
package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/ponack/touchstone/internal/connectors"
	"github.com/ponack/touchstone/internal/queue"
	"github.com/ponack/touchstone/internal/secretbox"
	"github.com/ponack/touchstone/internal/storage"
)

// Dispatcher binds the worker pool to its dependencies and starts
// processing jobs from River's queues.
type Dispatcher struct {
	pool      *pgxpool.Pool
	registry  *connectors.Registry
	secretKey string
	storage   *storage.Client
	river     *river.Client[pgx.Tx]
}

// New builds the worker dispatcher and registers every job type
// Touchstone knows how to process.
func New(pool *pgxpool.Pool, registry *connectors.Registry, secretKey string, store *storage.Client) (*Dispatcher, error) {
	workers := river.NewWorkers()
	river.AddWorker(workers, &ScanWorker{
		pool:      pool,
		registry:  registry,
		secretKey: secretKey,
		storage:   store,
	})

	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 4},
		},
		Workers: workers,
	})
	if err != nil {
		return nil, fmt.Errorf("river client: %w", err)
	}

	return &Dispatcher{
		pool:      pool,
		registry:  registry,
		secretKey: secretKey,
		storage:   store,
		river:     rc,
	}, nil
}

// Start begins job processing and blocks until ctx is cancelled, then
// drains in-flight jobs (30s budget).
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

// ScanWorker processes a scan job: loads the connector + sealed
// secret, runs the connector's Scan, uploads the normalized result
// to MinIO, and records the artifact key + resource count on the
// scans row. OPA evaluation against the resulting artifact (writing
// evidence_items) lands in PR D.3.
type ScanWorker struct {
	river.WorkerDefaults[queue.ScanJobArgs]
	pool      *pgxpool.Pool
	registry  *connectors.Registry
	secretKey string
	storage   *storage.Client
}

type scanContext struct {
	orgID       uuid.UUID
	connectorID uuid.UUID
	kind        connectors.Kind
	cfgRaw      []byte
	sealed      *string
}

func (w *ScanWorker) Work(ctx context.Context, job *river.Job[queue.ScanJobArgs]) error {
	scanID := job.Args.ScanID
	slog.Info("scan job picked up", "scan_id", scanID)

	sc, err := w.loadScanContext(ctx, scanID)
	if err != nil {
		return w.failScan(ctx, scanID, fmt.Sprintf("load: %v", err))
	}

	if err := w.markRunning(ctx, scanID); err != nil {
		return err
	}

	result, err := w.executeScan(ctx, sc)
	if err != nil {
		return w.failScan(ctx, scanID, err.Error())
	}

	key, err := w.uploadArtifact(ctx, sc.orgID, scanID, result)
	if err != nil {
		return w.failScan(ctx, scanID, fmt.Sprintf("upload: %v", err))
	}

	if err := w.markSucceeded(ctx, scanID, key, len(result.Resources)); err != nil {
		return err
	}

	slog.Info("scan job complete",
		"scan_id", scanID,
		"resources", len(result.Resources),
		"artifact_key", key,
	)
	return nil
}

func (w *ScanWorker) loadScanContext(ctx context.Context, scanID uuid.UUID) (*scanContext, error) {
	var sc scanContext
	err := w.pool.QueryRow(ctx, `
		SELECT s.org_id, s.connector_id, c.kind, c.config, c.secrets_ref
		FROM scans s
		JOIN connectors c ON c.id = s.connector_id
		WHERE s.id = $1
	`, scanID).Scan(&sc.orgID, &sc.connectorID, &sc.kind, &sc.cfgRaw, &sc.sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("scan %s not found", scanID)
	}
	if err != nil {
		return nil, err
	}
	return &sc, nil
}

func (w *ScanWorker) executeScan(ctx context.Context, sc *scanContext) (*connectors.ScanResult, error) {
	conn, ok := w.registry.Get(sc.kind)
	if !ok {
		return nil, fmt.Errorf("unknown connector kind %q", sc.kind)
	}

	var secret json.RawMessage
	if sc.sealed != nil && *sc.sealed != "" {
		plain, err := secretbox.Open([]byte(w.secretKey), *sc.sealed)
		if err != nil {
			return nil, fmt.Errorf("unseal secret: %w", err)
		}
		secret = plain
	}

	return conn.Scan(ctx, sc.cfgRaw, secret)
}

func (w *ScanWorker) uploadArtifact(ctx context.Context, orgID, scanID uuid.UUID, result *connectors.ScanResult) (string, error) {
	body, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	key := fmt.Sprintf("orgs/%s/scans/%s.json", orgID, scanID)
	if err := w.storage.PutEvidence(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil {
		return "", err
	}
	return key, nil
}

func (w *ScanWorker) markRunning(ctx context.Context, scanID uuid.UUID) error {
	_, err := w.pool.Exec(ctx, `
		UPDATE scans
		SET status = 'running', started_at = now()
		WHERE id = $1 AND status = 'queued'
	`, scanID)
	if err != nil {
		return fmt.Errorf("transition to running: %w", err)
	}
	return nil
}

func (w *ScanWorker) markSucceeded(ctx context.Context, scanID uuid.UUID, artifactKey string, count int) error {
	_, err := w.pool.Exec(ctx, `
		UPDATE scans
		SET status = 'succeeded',
		    finished_at = now(),
		    artifact_key = $1,
		    resources_count = $2
		WHERE id = $3
	`, artifactKey, count, scanID)
	if err != nil {
		return fmt.Errorf("transition to succeeded: %w", err)
	}
	return nil
}

func (w *ScanWorker) failScan(ctx context.Context, scanID uuid.UUID, msg string) error {
	slog.Error("scan failed", "scan_id", scanID, "error", msg)
	_, err := w.pool.Exec(ctx, `
		UPDATE scans
		SET status = 'failed', finished_at = now(), error_message = $1
		WHERE id = $2
	`, msg, scanID)
	// Return nil so River does not retry — the row already records the
	// failure. River retries by re-inserting via job opts, not by
	// re-running on Work errors.
	if err != nil {
		slog.Error("mark scan failed", "scan_id", scanID, "err", err)
	}
	return nil
}
