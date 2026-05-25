package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const defaultRegion = "us-east-1"

// buildAWSConfig produces an aws.Config that authenticates as the
// customer's audited principal. For "role" auth, the worker's
// ambient AWS credentials (env / file / instance metadata) bootstrap
// an STS:AssumeRole call into the customer-controlled role. For
// "key" auth, the static credentials decoded from the connector's
// sealed secret_ref are used directly.
func buildAWSConfig(ctx context.Context, cfg PublicConfig, sec Secret) (aws.Config, error) {
	region := defaultRegion
	if len(cfg.Regions) > 0 {
		region = cfg.Regions[0]
	}

	switch cfg.AuthMethod {
	case "role":
		base, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return aws.Config{}, fmt.Errorf("load default config: %w", err)
		}
		stsClient := sts.NewFromConfig(base)
		provider := stscreds.NewAssumeRoleProvider(stsClient, cfg.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "touchstone-scan"
			if cfg.ExternalID != "" {
				o.ExternalID = aws.String(cfg.ExternalID)
			}
		})
		out := base
		out.Credentials = aws.NewCredentialsCache(provider)
		return out, nil

	case "key":
		return awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(sec.AccessKeyID, sec.SecretAccessKey, ""),
			),
		)
	}

	return aws.Config{}, fmt.Errorf("unsupported auth_method: %q", cfg.AuthMethod)
}
