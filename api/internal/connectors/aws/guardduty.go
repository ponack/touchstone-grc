package aws

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanGuardDuty enumerates GuardDuty detectors across every
// configured region. Detectors are region-scoped — each region has
// its own. An account with GuardDuty "enabled" in the console
// actually has one detector per region.
//
// Per-region failures are logged and skipped. Regions where no
// detector exists yield no resource — the CC6.8 / CC7.3 rego
// interprets absence of detectors as failure.
func scanGuardDuty(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	var out []connectors.Resource
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := guardduty.NewFromConfig(regionCfg)

		list, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
		if err != nil {
			slog.Warn("guardduty ListDetectors failed", "region", region, "err", err)
			continue
		}

		for _, id := range list.DetectorIds {
			r, err := buildDetectorResource(ctx, client, id, region)
			if err != nil {
				slog.Warn("guardduty GetDetector failed", "region", region, "detector_id", id, "err", err)
				continue
			}
			out = append(out, r)
		}
	}
	return out, nil
}

func buildDetectorResource(ctx context.Context, client *guardduty.Client, detectorID, region string) (connectors.Resource, error) {
	out, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: &detectorID})
	if err != nil {
		return connectors.Resource{}, err
	}

	return connectors.Resource{
		Type: "aws.guardduty.detector",
		ID:   "arn:aws:guardduty:" + region + ":detector/" + detectorID,
		Attrs: map[string]any{
			"detector_id":                  detectorID,
			"region":                       region,
			"status":                       string(out.Status),
			"finding_publishing_frequency": string(out.FindingPublishingFrequency),
			"features":                     summarizeFeatures(out.Features),
		},
	}, nil
}

// summarizeFeatures flattens GuardDuty's nested feature list (S3 logs,
// EKS, malware protection, …) into a name → enabled map for OPA.
func summarizeFeatures(feats []gdtypes.DetectorFeatureConfigurationResult) map[string]bool {
	out := map[string]bool{}
	for _, f := range feats {
		out[string(f.Name)] = f.Status == gdtypes.FeatureStatusEnabled
	}
	return out
}
