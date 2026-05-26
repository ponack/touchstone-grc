package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanEC2 enumerates EC2 security groups across every configured
// region. SGs are region-scoped; the AWS SDK does not paginate
// across regions automatically, so we iterate.
//
// Per-region failures are logged and skipped. The audit prefers a
// partial result over zero evidence — one broken region (e.g.
// disabled SCP, transient API outage) should not invalidate the
// rest of the scan.
func scanEC2(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	var out []connectors.Resource
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := ec2.NewFromConfig(regionCfg)

		pager := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				slog.Warn("ec2 DescribeSecurityGroups failed", "region", region, "err", err)
				break
			}
			for _, sg := range page.SecurityGroups {
				out = append(out, buildSGResource(sg, region))
			}
		}
	}
	return out, nil
}

func buildSGResource(sg ec2types.SecurityGroup, region string) connectors.Resource {
	groupID := aws.ToString(sg.GroupId)
	return connectors.Resource{
		Type: "aws.ec2.security_group",
		ID:   fmt.Sprintf("arn:aws:ec2:%s::security-group/%s", region, groupID),
		Attrs: map[string]any{
			"group_id":      groupID,
			"group_name":    aws.ToString(sg.GroupName),
			"vpc_id":        aws.ToString(sg.VpcId),
			"description":   aws.ToString(sg.Description),
			"region":        region,
			"ingress_rules": normalizeRules(sg.IpPermissions),
			"egress_rules":  normalizeRules(sg.IpPermissionsEgress),
		},
	}
}

// normalizeRules flattens an SG rule list to a shape OPA policies can
// query without juggling pointers or AWS protocol idioms. "-1"
// (all-protocols) rules surface as full 0–65535 ranges so the rego
// can use a single comparison instead of branching on protocol.
func normalizeRules(perms []ec2types.IpPermission) []map[string]any {
	out := make([]map[string]any, 0, len(perms))
	for _, p := range perms {
		proto := aws.ToString(p.IpProtocol)
		from := int32(0)
		to := int32(65535)
		if proto != "-1" {
			if p.FromPort != nil {
				from = *p.FromPort
			}
			if p.ToPort != nil {
				to = *p.ToPort
			}
		}

		v4 := make([]string, 0, len(p.IpRanges))
		for _, r := range p.IpRanges {
			v4 = append(v4, aws.ToString(r.CidrIp))
		}
		v6 := make([]string, 0, len(p.Ipv6Ranges))
		for _, r := range p.Ipv6Ranges {
			v6 = append(v6, aws.ToString(r.CidrIpv6))
		}

		out = append(out, map[string]any{
			"protocol":   proto,
			"from_port":  from,
			"to_port":    to,
			"ipv4_cidrs": v4,
			"ipv6_cidrs": v6,
		})
	}
	return out
}
