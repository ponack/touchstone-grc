package aws

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanCloudTrail enumerates CloudTrail trails across every configured
// region and pairs each with its current logging status. Trails are
// region-scoped (a "multi-region" trail still has a home region) so
// we iterate; ARN is the natural dedupe key when the same multi-region
// trail surfaces in multiple regions via shadow listings.
//
// Per-region or per-trail failures are logged and skipped — the
// scanner stays honest about partial coverage rather than aborting
// on a single bad region.
func scanCloudTrail(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	seen := map[string]struct{}{}
	var out []connectors.Resource

	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := cloudtrail.NewFromConfig(regionCfg)

		desc, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
			IncludeShadowTrails: aws.Bool(true),
		})
		if err != nil {
			slog.Warn("cloudtrail DescribeTrails failed", "region", region, "err", err)
			continue
		}

		for _, t := range desc.TrailList {
			arn := aws.ToString(t.TrailARN)
			if arn == "" {
				continue
			}
			if _, dup := seen[arn]; dup {
				continue
			}
			seen[arn] = struct{}{}

			r, err := buildTrailResource(ctx, client, t)
			if err != nil {
				slog.Warn("cloudtrail trail enrichment failed", "arn", arn, "err", err)
				continue
			}
			out = append(out, r)
		}
	}
	return out, nil
}

func buildTrailResource(ctx context.Context, client *cloudtrail.Client, t cttypes.Trail) (connectors.Resource, error) {
	arn := aws.ToString(t.TrailARN)

	// GetTrailStatus tells us whether the trail is actively logging —
	// the bit DescribeTrails does not expose. Best-effort: if the
	// status call fails, surface is_logging=false so the policy
	// catches the gap rather than silently passing.
	isLogging := false
	status, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN})
	if err != nil {
		slog.Warn("cloudtrail GetTrailStatus failed", "arn", arn, "err", err)
	} else if status.IsLogging != nil {
		isLogging = *status.IsLogging
	}

	return connectors.Resource{
		Type: "aws.cloudtrail.trail",
		ID:   arn,
		Attrs: map[string]any{
			"name":                          aws.ToString(t.Name),
			"home_region":                   aws.ToString(t.HomeRegion),
			"is_multi_region":               aws.ToBool(t.IsMultiRegionTrail),
			"include_global_service_events": aws.ToBool(t.IncludeGlobalServiceEvents),
			"log_file_validation_enabled":   aws.ToBool(t.LogFileValidationEnabled),
			"is_logging":                    isLogging,
			"s3_bucket_name":                aws.ToString(t.S3BucketName),
			"kms_key_id":                    aws.ToString(t.KmsKeyId),
			"cloudwatch_logs_log_group_arn": aws.ToString(t.CloudWatchLogsLogGroupArn),
		},
	}, nil
}
