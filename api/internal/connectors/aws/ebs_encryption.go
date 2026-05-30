package aws

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanEBSEncryption emits one aws.ec2.ebs_encryption_region resource
// per configured region capturing the EBS encryption-by-default
// flag. CIS 2.2.1 requires this flag set in every region in scope —
// missing the flag means new EBS volumes can be created unencrypted.
//
// Per-region failures are logged but the region is still emitted
// with enabled=false so the rule surfaces the gap rather than
// silently passing.
func scanEBSEncryption(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	out := make([]connectors.Resource, 0, len(regions))
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := ec2.NewFromConfig(regionCfg)

		enabled := false
		resp, err := client.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
		if err != nil {
			slog.Warn("ec2 GetEbsEncryptionByDefault failed", "region", region, "err", err)
		} else {
			enabled = aws.ToBool(resp.EbsEncryptionByDefault)
		}

		out = append(out, connectors.Resource{
			Type: "aws.ec2.ebs_encryption_region",
			ID:   "aws-ec2-ebs-encryption://" + region,
			Attrs: map[string]any{
				"region":  region,
				"enabled": enabled,
			},
		})
	}
	return out, nil
}
