// Package queue wraps the River-backed job queue. The serve command
// uses Client in enqueue-only mode; the worker command builds a full
// River client via the worker package. Both share the job-argument
// types defined here so the kind strings stay in sync across the two
// processes.
package queue

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

// ScanJobArgs is the payload of a scan-execution job. The worker
// reads the rest of the scan + connector context from the database.
type ScanJobArgs struct {
	ScanID uuid.UUID `json:"scan_id"`
}

func (ScanJobArgs) Kind() string { return "scan" }

func (ScanJobArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 3,
		Priority:    1,
		Queue:       river.QueueDefault,
	}
}

// Client is the enqueue-only wrapper used by the serve process.
type Client struct {
	river *river.Client[pgx.Tx]
}

// New builds an enqueue-only River client backed by pool. The caller
// must invoke Stop during shutdown to release the embedded pollers.
func New(pool *pgxpool.Pool) (*Client, error) {
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	if err != nil {
		return nil, fmt.Errorf("river client: %w", err)
	}
	return &Client{river: rc}, nil
}

// EnqueueScan inserts a scan-execution job for scanID.
func (c *Client) EnqueueScan(ctx context.Context, scanID uuid.UUID) error {
	_, err := c.river.Insert(ctx, ScanJobArgs{ScanID: scanID}, nil)
	return err
}

// EnqueueScanTx inserts a scan-execution job inside an existing pgx
// transaction so the scans row and the queued job land atomically.
func (c *Client) EnqueueScanTx(ctx context.Context, tx pgx.Tx, scanID uuid.UUID) error {
	_, err := c.river.InsertTx(ctx, tx, ScanJobArgs{ScanID: scanID}, nil)
	return err
}
