package aws

import (
	"log/slog"

	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanAccessAnalyzer emits one aws.accessanalyzer.region resource per
// configured region with a count of analyzers + whether any is ACTIVE.
// CIS 1.21 expects every region in scope to carry at least one active
// analyzer; the rego inspects has_active_analyzer per region.
//
// Per-region failures are logged and the region is still emitted with
// analyzer_count = 0 + has_active_analyzer = false so the rule still
// flags the gap.
func scanAccessAnalyzer(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	out := make([]connectors.Resource, 0, len(regions))
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := accessanalyzer.NewFromConfig(regionCfg)

		count, hasActive, err := listAnalyzersInRegion(ctx, client)
		if err != nil {
			slog.Warn("accessanalyzer ListAnalyzers failed", "region", region, "err", err)
		}

		out = append(out, connectors.Resource{
			Type: "aws.accessanalyzer.region",
			ID:   "aws-accessanalyzer://" + region,
			Attrs: map[string]any{
				"region":              region,
				"analyzer_count":      count,
				"has_active_analyzer": hasActive,
			},
		})
	}
	return out, nil
}

func listAnalyzersInRegion(ctx context.Context, client *accessanalyzer.Client) (int, bool, error) {
	count := 0
	hasActive := false
	pager := accessanalyzer.NewListAnalyzersPaginator(client, &accessanalyzer.ListAnalyzersInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return count, hasActive, err
		}
		for _, a := range page.Analyzers {
			count++
			if a.Status == aatypes.AnalyzerStatusActive {
				hasActive = true
			}
		}
	}
	return count, hasActive, nil
}
