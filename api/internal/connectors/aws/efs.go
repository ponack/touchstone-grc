package aws

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanEFS enumerates EFS file systems across every configured region
// and emits one aws.efs.file_system resource per FS. CIS 2.4.1
// reads the encrypted flag; other EFS hygiene rules slot into
// future batches.
//
// Per-region failures are logged and skipped — partial evidence is
// better than no evidence when one region's API is flaky.
func scanEFS(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	var out []connectors.Resource
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		client := efs.NewFromConfig(regionCfg)

		pager := efs.NewDescribeFileSystemsPaginator(client, &efs.DescribeFileSystemsInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				slog.Warn("efs DescribeFileSystems failed", "region", region, "err", err)
				break
			}
			for _, fs := range page.FileSystems {
				out = append(out, connectors.Resource{
					Type: "aws.efs.file_system",
					ID:   aws.ToString(fs.FileSystemArn),
					Attrs: map[string]any{
						"file_system_id":   aws.ToString(fs.FileSystemId),
						"name":             aws.ToString(fs.Name),
						"region":           region,
						"encrypted":        aws.ToBool(fs.Encrypted),
						"kms_key_id":       aws.ToString(fs.KmsKeyId),
						"life_cycle_state": string(fs.LifeCycleState),
					},
				})
			}
		}
	}
	return out, nil
}
