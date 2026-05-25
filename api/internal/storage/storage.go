// Package storage wraps MinIO (or any S3-compatible target) for two
// buckets: evidence (raw scan artifacts) and artifacts (auditor
// reports / exports). Both buckets are created on first use so
// fresh deployments don't need an out-of-band "create bucket" step.
package storage

import (
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/ponack/touchstone/internal/config"
)

type Client struct {
	minio        *minio.Client
	evidenceBkt  string
	artifactsBkt string
}

func New(cfg *config.Config) (*Client, error) {
	mc, err := minio.New(cfg.MinIO.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinIO.AccessKey, cfg.MinIO.SecretKey, ""),
		Secure: cfg.MinIO.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("minio client: %w", err)
	}
	return &Client{
		minio:        mc,
		evidenceBkt:  cfg.MinIO.BucketEvidence,
		artifactsBkt: cfg.MinIO.BucketArtifacts,
	}, nil
}

// EnsureBuckets creates the evidence + artifacts buckets if they
// don't already exist. Idempotent — safe to call on every startup.
func (c *Client) EnsureBuckets(ctx context.Context) error {
	for _, b := range []string{c.evidenceBkt, c.artifactsBkt} {
		exists, err := c.minio.BucketExists(ctx, b)
		if err != nil {
			return fmt.Errorf("check bucket %s: %w", b, err)
		}
		if exists {
			continue
		}
		if err := c.minio.MakeBucket(ctx, b, minio.MakeBucketOptions{}); err != nil {
			return fmt.Errorf("create bucket %s: %w", b, err)
		}
	}
	return nil
}

// PutEvidence uploads a scan artifact under key into the evidence
// bucket. Content type is set to application/json since every
// artifact today is a normalized resource graph.
func (c *Client) PutEvidence(ctx context.Context, key string, body io.Reader, size int64) error {
	_, err := c.minio.PutObject(ctx, c.evidenceBkt, key, body, size, minio.PutObjectOptions{
		ContentType: "application/json",
	})
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	return nil
}

// GetEvidence streams the artifact stored under key. Caller closes.
func (c *Client) GetEvidence(ctx context.Context, key string) (io.ReadCloser, error) {
	obj, err := c.minio.GetObject(ctx, c.evidenceBkt, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", key, err)
	}
	return obj, nil
}
