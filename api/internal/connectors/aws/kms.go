package aws

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanKMS enumerates customer-managed KMS keys across every configured
// region and emits one aws.kms.key resource per CMK. The scanner
// pre-computes:
//
//   - rotation_enabled: from GetKeyRotationStatus (symmetric CMKs only;
//     AWS rejects the call on asymmetric / HMAC keys).
//   - enabled: derived from the key state — CIS 3.8 only flags
//     currently-active keys.
//
// AWS-managed keys (KeyManager=AWS) auto-rotate every year and are
// excluded from the scanner output entirely — they cannot satisfy
// or fail CIS 3.8.
func scanKMS(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	var out []connectors.Resource
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := kms.NewFromConfig(regionCfg)

		keys, err := listKMSKeys(ctx, client)
		if err != nil {
			slog.Warn("kms ListKeys failed", "region", region, "err", err)
			continue
		}
		for _, k := range keys {
			r, ok := buildKMSKeyResource(ctx, client, k, region)
			if !ok {
				continue
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// listKMSKeys collects every key ARN in the region; paginated.
func listKMSKeys(ctx context.Context, client *kms.Client) ([]kmstypes.KeyListEntry, error) {
	var out []kmstypes.KeyListEntry
	pager := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Keys...)
	}
	return out, nil
}

// buildKMSKeyResource returns (resource, true) for customer-managed
// symmetric CMKs the scanner could enrich. Returns (_, false) for
// AWS-managed keys or unsupported key types — those are out of CIS
// 3.8 scope.
func buildKMSKeyResource(ctx context.Context, client *kms.Client, entry kmstypes.KeyListEntry, region string) (connectors.Resource, bool) {
	id := aws.ToString(entry.KeyId)
	desc, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: entry.KeyId})
	if err != nil {
		slog.Warn("kms DescribeKey failed", "key", id, "region", region, "err", err)
		return connectors.Resource{}, false
	}
	if desc.KeyMetadata == nil {
		return connectors.Resource{}, false
	}
	md := desc.KeyMetadata
	// CIS 3.8 only targets customer-managed CMKs.
	if md.KeyManager != kmstypes.KeyManagerTypeCustomer {
		return connectors.Resource{}, false
	}

	rotationEnabled := false
	rotationApplicable := md.KeySpec == kmstypes.KeySpecSymmetricDefault
	if rotationApplicable {
		rot, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: entry.KeyId})
		if err != nil {
			slog.Warn("kms GetKeyRotationStatus failed", "key", id, "region", region, "err", err)
		} else {
			rotationEnabled = rot.KeyRotationEnabled
		}
	}

	return connectors.Resource{
		Type: "aws.kms.key",
		ID:   aws.ToString(md.Arn),
		Attrs: map[string]any{
			"key_id":              aws.ToString(md.KeyId),
			"arn":                 aws.ToString(md.Arn),
			"region":              region,
			"key_manager":         string(md.KeyManager),
			"key_spec":            string(md.KeySpec),
			"enabled":             md.Enabled,
			"key_state":           string(md.KeyState),
			"rotation_applicable": rotationApplicable,
			"rotation_enabled":    rotationEnabled,
		},
	}, true
}
