package aws

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanVPC enumerates VPCs across every configured region and emits
// one aws.ec2.vpc resource per VPC. The scanner pre-computes
// flow_logs_active = "at least one ACTIVE flow log targets this
// VPC's resource id". CIS 3.9 reads the boolean directly.
//
// Per-region failures are logged and skipped — partial evidence
// beats no evidence.
func scanVPC(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	var out []connectors.Resource
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := ec2.NewFromConfig(regionCfg)

		vpcs, err := listVPCs(ctx, client)
		if err != nil {
			slog.Warn("ec2 DescribeVpcs failed", "region", region, "err", err)
			continue
		}
		if len(vpcs) == 0 {
			continue
		}

		activeFlowLogVPCs, err := listVPCsWithActiveFlowLogs(ctx, client)
		if err != nil {
			slog.Warn("ec2 DescribeFlowLogs failed", "region", region, "err", err)
			activeFlowLogVPCs = nil
		}

		for _, v := range vpcs {
			id := aws.ToString(v.VpcId)
			out = append(out, connectors.Resource{
				Type: "aws.ec2.vpc",
				ID:   "aws-ec2://" + region + "/vpcs/" + id,
				Attrs: map[string]any{
					"vpc_id":           id,
					"cidr_block":       aws.ToString(v.CidrBlock),
					"region":           region,
					"is_default":       aws.ToBool(v.IsDefault),
					"flow_logs_active": activeFlowLogVPCs[id],
				},
			})
		}
	}
	return out, nil
}

func listVPCs(ctx context.Context, client *ec2.Client) ([]ec2types.Vpc, error) {
	var out []ec2types.Vpc
	pager := ec2.NewDescribeVpcsPaginator(client, &ec2.DescribeVpcsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Vpcs...)
	}
	return out, nil
}

// listVPCsWithActiveFlowLogs returns a set of VPC IDs that have at
// least one ACTIVE flow log. CIS 3.9 doesn't care about LogDestination
// type (S3 / CloudWatch Logs / Kinesis) — just that flow capture is
// running.
func listVPCsWithActiveFlowLogs(ctx context.Context, client *ec2.Client) (map[string]bool, error) {
	covered := map[string]bool{}
	pager := ec2.NewDescribeFlowLogsPaginator(client, &ec2.DescribeFlowLogsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return covered, err
		}
		for _, fl := range page.FlowLogs {
			if aws.ToString(fl.FlowLogStatus) != "ACTIVE" {
				continue
			}
			rid := aws.ToString(fl.ResourceId)
			// ResourceId for VPC-scoped flow logs is the vpc-id
			// literal. Subnet- and ENI-scoped flow logs use other
			// prefixes and don't satisfy CIS 3.9.
			if rid == "" {
				continue
			}
			covered[rid] = true
		}
	}
	return covered, nil
}
