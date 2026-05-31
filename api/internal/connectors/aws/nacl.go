package aws

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanNetworkACLs enumerates Network ACLs across every configured
// region. Each NACL becomes an aws.ec2.network_acl resource with a
// flattened ingress_rules list (CIS 5.1 only cares about
// ingress / Egress=false entries — egress NACL rules don't gate
// inbound traffic).
//
// Per-region failures are logged and skipped.
func scanNetworkACLs(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	var out []connectors.Resource
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := ec2.NewFromConfig(regionCfg)

		pager := ec2.NewDescribeNetworkAclsPaginator(client, &ec2.DescribeNetworkAclsInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				slog.Warn("ec2 DescribeNetworkAcls failed", "region", region, "err", err)
				break
			}
			for _, n := range page.NetworkAcls {
				out = append(out, buildNACLResource(n, region))
			}
		}
	}
	return out, nil
}

func buildNACLResource(n ec2types.NetworkAcl, region string) connectors.Resource {
	id := aws.ToString(n.NetworkAclId)
	return connectors.Resource{
		Type: "aws.ec2.network_acl",
		ID:   "aws-ec2://" + region + "/network-acls/" + id,
		Attrs: map[string]any{
			"network_acl_id": id,
			"vpc_id":         aws.ToString(n.VpcId),
			"region":         region,
			"is_default":     aws.ToBool(n.IsDefault),
			"ingress_rules":  flattenNACLEntries(n.Entries, false),
		},
	}
}

// flattenNACLEntries returns the entries matching the requested
// direction (Egress=false → ingress, Egress=true → egress).
// CIS 5.1 only inspects ingress; emit only the slice the rule
// needs to keep the resource payload tight.
func flattenNACLEntries(entries []ec2types.NetworkAclEntry, wantEgress bool) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		if aws.ToBool(e.Egress) != wantEgress {
			continue
		}
		from := 0
		to := 65535
		if e.PortRange != nil {
			from = int(aws.ToInt32(e.PortRange.From))
			to = int(aws.ToInt32(e.PortRange.To))
		}
		out = append(out, map[string]any{
			"rule_number":     aws.ToInt32(e.RuleNumber),
			"protocol":        aws.ToString(e.Protocol),
			"rule_action":     string(e.RuleAction),
			"cidr_block":      aws.ToString(e.CidrBlock),
			"ipv6_cidr_block": aws.ToString(e.Ipv6CidrBlock),
			"from_port":       from,
			"to_port":         to,
		})
	}
	return out
}
