package aws

import (
	"context"
	"errors"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/smithy-go"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanSecurityHub probes every configured region for an enabled
// Security Hub Hub and lists the standards subscribed in each. Hub
// activation is region-scoped — many accounts only enable it in one
// or two regions, which is the failure mode CC7.1 catches.
//
// "Hub not enabled in this region" surfaces from DescribeHub as
// InvalidAccessException ("Account is not subscribed to AWS Security
// Hub"). That is expected and is *not* logged — the absence of a
// resource for that region is the audit signal.
func scanSecurityHub(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	var out []connectors.Resource
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := securityhub.NewFromConfig(regionCfg)

		hub, err := client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) && ae.ErrorCode() == "InvalidAccessException" {
				// Hub not enabled in this region — expected, skip silently.
				continue
			}
			slog.Warn("securityhub DescribeHub failed", "region", region, "err", err)
			continue
		}

		standards, err := listEnabledStandards(ctx, client)
		if err != nil {
			slog.Warn("securityhub GetEnabledStandards failed",
				"region", region, "hub", aws.ToString(hub.HubArn), "err", err)
			// Continue with an empty standards list so the rego sees the
			// gap rather than silently dropping the row.
		}

		out = append(out, connectors.Resource{
			Type: "aws.securityhub.hub",
			ID:   aws.ToString(hub.HubArn),
			Attrs: map[string]any{
				"region":               region,
				"subscribed_at":        aws.ToString(hub.SubscribedAt),
				"auto_enable_controls": aws.ToBool(hub.AutoEnableControls),
				"subscribed_standards": standards,
			},
		})
	}
	return out, nil
}

func listEnabledStandards(ctx context.Context, client *securityhub.Client) ([]string, error) {
	out := []string{}
	pager := securityhub.NewGetEnabledStandardsPaginator(client, &securityhub.GetEnabledStandardsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		for _, s := range page.StandardsSubscriptions {
			out = append(out, aws.ToString(s.StandardsArn))
		}
	}
	return out, nil
}
