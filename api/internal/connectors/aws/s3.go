package aws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanS3 enumerates every bucket in the account and surfaces the
// surfaces SOC 2 CC6.6 / CC6.7 policies care about: Public Access
// Block, policy-derived public flag, default encryption, versioning.
//
// Per-bucket lookups are best-effort: a failure on one bucket logs
// and skips rather than aborting the scan. That matches the IAM
// scanner's contract and avoids one stale bucket invalidating the
// rest of the audit.
func scanS3(ctx context.Context, awsCfg aws.Config) ([]connectors.Resource, error) {
	client := s3.NewFromConfig(awsCfg)

	listOut, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("s3:ListBuckets: %w", err)
	}

	out := make([]connectors.Resource, 0, len(listOut.Buckets))
	for _, b := range listOut.Buckets {
		r, err := buildBucketResource(ctx, client, b)
		if err != nil {
			slog.Warn("s3 bucket enrichment failed",
				"bucket", aws.ToString(b.Name), "err", err)
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func buildBucketResource(ctx context.Context, client *s3.Client, b s3types.Bucket) (connectors.Resource, error) {
	name := aws.ToString(b.Name)
	arn := "arn:aws:s3:::" + name

	bpa := readPublicAccessBlock(ctx, client, name)
	publicByPolicy := readPolicyStatusIsPublic(ctx, client, name)
	enc := readEncryption(ctx, client, name)
	ver := readVersioning(ctx, client, name)

	return connectors.Resource{
		Type: "aws.s3.bucket",
		ID:   arn,
		Attrs: map[string]any{
			"name":                name,
			"creation_date":       aws.ToTime(b.CreationDate),
			"public_access_block": bpa,
			"policy_status": map[string]any{
				"is_public": publicByPolicy,
			},
			"encryption":            enc,
			"versioning_enabled":    ver.enabled,
			"versioning_mfa_delete": ver.mfaDelete,
		},
	}, nil
}

// ── Public Access Block ──────────────────────────────────────────────────────

// Returns the four BPA flags, defaulting every one to false when the
// bucket has no explicit configuration (a real "block public access"
// posture must be configured — absence does not imply restriction).
func readPublicAccessBlock(ctx context.Context, client *s3.Client, name string) map[string]any {
	out, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &name})
	if err != nil {
		// "NoSuchPublicAccessBlockConfiguration" is expected when no
		// BPA has been set. Any other error is logged but treated as
		// "no protection" — the conservative choice for an audit.
		var ae smithy.APIError
		if !errors.As(err, &ae) || ae.ErrorCode() != "NoSuchPublicAccessBlockConfiguration" {
			slog.Warn("s3 GetPublicAccessBlock failed", "bucket", name, "err", err)
		}
		return map[string]any{
			"block_public_acls":       false,
			"ignore_public_acls":      false,
			"block_public_policy":     false,
			"restrict_public_buckets": false,
		}
	}
	cfg := out.PublicAccessBlockConfiguration
	if cfg == nil {
		return map[string]any{
			"block_public_acls":       false,
			"ignore_public_acls":      false,
			"block_public_policy":     false,
			"restrict_public_buckets": false,
		}
	}
	return map[string]any{
		"block_public_acls":       aws.ToBool(cfg.BlockPublicAcls),
		"ignore_public_acls":      aws.ToBool(cfg.IgnorePublicAcls),
		"block_public_policy":     aws.ToBool(cfg.BlockPublicPolicy),
		"restrict_public_buckets": aws.ToBool(cfg.RestrictPublicBuckets),
	}
}

// ── Policy status ────────────────────────────────────────────────────────────

func readPolicyStatusIsPublic(ctx context.Context, client *s3.Client, name string) bool {
	out, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: &name})
	if err != nil {
		// "NoSuchBucketPolicy" returns from buckets with no policy;
		// AWS considers them not-public-by-policy. Treat as false.
		var ae smithy.APIError
		if !errors.As(err, &ae) || ae.ErrorCode() != "NoSuchBucketPolicy" {
			slog.Warn("s3 GetBucketPolicyStatus failed", "bucket", name, "err", err)
		}
		return false
	}
	if out.PolicyStatus == nil {
		return false
	}
	return aws.ToBool(out.PolicyStatus.IsPublic)
}

// ── Default encryption ───────────────────────────────────────────────────────

func readEncryption(ctx context.Context, client *s3.Client, name string) map[string]any {
	out, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &name})
	if err != nil {
		var ae smithy.APIError
		if !errors.As(err, &ae) || ae.ErrorCode() != "ServerSideEncryptionConfigurationNotFoundError" {
			slog.Warn("s3 GetBucketEncryption failed", "bucket", name, "err", err)
		}
		return map[string]any{"enabled": false, "algorithm": "", "kms_key": ""}
	}

	enabled := false
	algorithm := ""
	kmsKey := ""
	if out.ServerSideEncryptionConfiguration != nil {
		for _, rule := range out.ServerSideEncryptionConfiguration.Rules {
			if rule.ApplyServerSideEncryptionByDefault == nil {
				continue
			}
			enabled = true
			algorithm = string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
			kmsKey = aws.ToString(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID)
			break
		}
	}
	return map[string]any{
		"enabled":   enabled,
		"algorithm": algorithm,
		"kms_key":   kmsKey,
	}
}

// ── Versioning ───────────────────────────────────────────────────────────────

type versioningInfo struct {
	enabled   bool
	mfaDelete bool
}

func readVersioning(ctx context.Context, client *s3.Client, name string) versioningInfo {
	out, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &name})
	if err != nil {
		slog.Warn("s3 GetBucketVersioning failed", "bucket", name, "err", err)
		return versioningInfo{}
	}
	return versioningInfo{
		enabled:   out.Status == s3types.BucketVersioningStatusEnabled,
		mfaDelete: out.MFADelete == s3types.MFADeleteStatusEnabled,
	}
}
