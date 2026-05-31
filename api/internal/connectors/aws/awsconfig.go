package aws

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanAWSConfig emits one aws.config.region resource per configured
// region capturing whether the AWS Config service is recording
// configuration changes there. CIS 3.5 needs at least one recorder
// per region that:
//
//   - has its recording_group configured for all supported resources
//     (or all + global), AND
//   - is reported as actively recording by the recorder status.
//
// Per-region failures degrade to has_active_recorder=false rather
// than failing the whole scan — the audit prefers a flagged region
// over no result.
func scanAWSConfig(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	out := make([]connectors.Resource, 0, len(regions))
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := configservice.NewFromConfig(regionCfg)

		count, hasActive := readConfigRecorders(ctx, client, region)
		out = append(out, connectors.Resource{
			Type: "aws.config.region",
			ID:   "aws-config://" + region,
			Attrs: map[string]any{
				"region":              region,
				"recorder_count":      count,
				"has_active_recorder": hasActive,
			},
		})
	}
	return out, nil
}

// readConfigRecorders returns the count of recorders defined in the
// region and whether at least one is configured for all-supported
// resources AND currently recording.
func readConfigRecorders(ctx context.Context, client *configservice.Client, region string) (int, bool) {
	desc, err := client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		slog.Warn("config DescribeConfigurationRecorders failed", "region", region, "err", err)
		return 0, false
	}
	if len(desc.ConfigurationRecorders) == 0 {
		return 0, false
	}

	statuses, err := client.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		slog.Warn("config DescribeConfigurationRecorderStatus failed", "region", region, "err", err)
		// Still return the count we know — has_active_recorder stays
		// false so CIS 3.5 surfaces the gap.
		return len(desc.ConfigurationRecorders), false
	}

	recording := map[string]bool{}
	for _, s := range statuses.ConfigurationRecordersStatus {
		recording[aws.ToString(s.Name)] = s.Recording
	}

	for _, r := range desc.ConfigurationRecorders {
		if r.RecordingGroup == nil {
			continue
		}
		// "All-supported" coverage means AllSupported=true. Some
		// operators opt to record specific resource types — those
		// don't satisfy CIS 3.5's account-wide expectation.
		if !r.RecordingGroup.AllSupported {
			continue
		}
		if recording[aws.ToString(r.Name)] {
			return len(desc.ConfigurationRecorders), true
		}
	}
	return len(desc.ConfigurationRecorders), false
}
