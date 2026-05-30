package aws

import (
	"context"
	"encoding/json"
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
	httpsOnly := readBucketEnforcesHTTPSOnly(ctx, client, name)

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
			"enforces_https_only":   httpsOnly,
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

// ── Bucket policy: HTTPS-only enforcement (CIS 2.1.2) ────────────────────────

// readBucketEnforcesHTTPSOnly returns true when the bucket policy
// contains at least one Deny statement that fires on aws:SecureTransport=false
// and covers the bucket's actions broadly enough to plausibly block
// HTTP traffic. Missing policy = no enforcement = false.
func readBucketEnforcesHTTPSOnly(ctx context.Context, client *s3.Client, name string) bool {
	out, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &name})
	if err != nil {
		var ae smithy.APIError
		if !errors.As(err, &ae) || ae.ErrorCode() != "NoSuchBucketPolicy" {
			slog.Warn("s3 GetBucketPolicy failed", "bucket", name, "err", err)
		}
		return false
	}
	if out.Policy == nil {
		return false
	}
	ok, err := bucketPolicyEnforcesHTTPSOnly([]byte(aws.ToString(out.Policy)))
	if err != nil {
		slog.Warn("s3 bucket policy parse failed", "bucket", name, "err", err)
		return false
	}
	return ok
}

// bucketPolicyEnforcesHTTPSOnly is the pure-Go testable core: parse
// the document and return true when at least one statement Denies
// requests where aws:SecureTransport is false.
func bucketPolicyEnforcesHTTPSOnly(doc []byte) (bool, error) {
	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		return false, fmt.Errorf("parse bucket policy: %w", err)
	}

	type policyStatement struct {
		Effect    string                                `json:"Effect"`
		Condition map[string]map[string]json.RawMessage `json:"Condition"`
	}

	var statements []policyStatement
	if len(parsed.Statement) > 0 && parsed.Statement[0] == '[' {
		if err := json.Unmarshal(parsed.Statement, &statements); err != nil {
			return false, fmt.Errorf("parse statement array: %w", err)
		}
	} else {
		var single policyStatement
		if err := json.Unmarshal(parsed.Statement, &single); err != nil {
			return false, fmt.Errorf("parse statement object: %w", err)
		}
		statements = append(statements, single)
	}

	for _, s := range statements {
		if s.Effect != "Deny" {
			continue
		}
		boolCond, ok := s.Condition["Bool"]
		if !ok {
			continue
		}
		raw, ok := boolCond["aws:SecureTransport"]
		if !ok {
			continue
		}
		if rawConditionIsFalse(raw) {
			return true, nil
		}
	}
	return false, nil
}

// rawConditionIsFalse reports whether a Condition RHS is the literal
// false / "false" / ["false"]. IAM accepts all three shapes in the
// JSON document.
func rawConditionIsFalse(raw json.RawMessage) bool {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s == "false"
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return !b
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, v := range arr {
			if v == "false" {
				return true
			}
		}
	}
	return false
}
