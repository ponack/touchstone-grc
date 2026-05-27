package aws

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanRDS enumerates RDS DB instances across every configured region
// and surfaces the attributes the CC7.5 (recovery) rego cares about:
// backup retention, deletion protection, storage encryption, Multi-AZ,
// public accessibility.
//
// Aurora clusters and snapshots are out of scope for this PR — they
// will land in a follow-up alongside the standalone clusters rego.
//
// Per-region failures are logged and skipped.
func scanRDS(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	var out []connectors.Resource
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := rds.NewFromConfig(regionCfg)

		pager := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				slog.Warn("rds DescribeDBInstances failed", "region", region, "err", err)
				break
			}
			for _, inst := range page.DBInstances {
				out = append(out, buildInstanceResource(inst, region))
			}
		}
	}
	return out, nil
}

func buildInstanceResource(inst rdstypes.DBInstance, region string) connectors.Resource {
	return connectors.Resource{
		Type: "aws.rds.db_instance",
		ID:   aws.ToString(inst.DBInstanceArn),
		Attrs: map[string]any{
			"db_instance_identifier":  aws.ToString(inst.DBInstanceIdentifier),
			"engine":                  aws.ToString(inst.Engine),
			"engine_version":          aws.ToString(inst.EngineVersion),
			"region":                  region,
			"status":                  aws.ToString(inst.DBInstanceStatus),
			"backup_retention_period": aws.ToInt32(inst.BackupRetentionPeriod),
			"deletion_protection":     aws.ToBool(inst.DeletionProtection),
			"storage_encrypted":       aws.ToBool(inst.StorageEncrypted),
			"multi_az":                aws.ToBool(inst.MultiAZ),
			"publicly_accessible":     aws.ToBool(inst.PubliclyAccessible),
			"iam_database_auth":       aws.ToBool(inst.IAMDatabaseAuthenticationEnabled),
		},
	}
}
