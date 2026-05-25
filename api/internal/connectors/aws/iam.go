package aws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanIAM enumerates IAM users + their access keys + MFA devices +
// console-access flag. These are the surfaces SOC 2 CC6.1 / CC6.3
// policies will evaluate against. Other IAM resources (roles,
// policies, groups) are intentionally out of scope for this PR.
//
// Per-user lookups (access keys, MFA, login profile) are best-effort:
// a failure on one user is logged and skipped rather than aborting
// the whole scan. The alternative — failing the entire scan because
// one user record went stale mid-pagination — produces worse evidence
// than a partial result with a logged warning.
func scanIAM(ctx context.Context, awsCfg aws.Config) ([]connectors.Resource, error) {
	client := iam.NewFromConfig(awsCfg)
	var resources []connectors.Resource

	pager := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam:ListUsers: %w", err)
		}
		for _, u := range page.Users {
			r, err := buildUserResource(ctx, client, u)
			if err != nil {
				slog.Warn("iam user enrichment failed", "user", aws.ToString(u.UserName), "err", err)
				continue
			}
			resources = append(resources, r)
		}
	}

	return resources, nil
}

func buildUserResource(ctx context.Context, client *iam.Client, u iamtypes.User) (connectors.Resource, error) {
	userName := aws.ToString(u.UserName)

	hasConsole, err := userHasConsoleAccess(ctx, client, u.UserName)
	if err != nil {
		return connectors.Resource{}, fmt.Errorf("login profile: %w", err)
	}

	accessKeys, err := listAccessKeys(ctx, client, u.UserName)
	if err != nil {
		return connectors.Resource{}, fmt.Errorf("access keys: %w", err)
	}

	mfaDevices, err := listMFADevices(ctx, client, u.UserName)
	if err != nil {
		return connectors.Resource{}, fmt.Errorf("mfa devices: %w", err)
	}

	return connectors.Resource{
		Type: "aws.iam.user",
		ID:   aws.ToString(u.Arn),
		Attrs: map[string]any{
			"user_name":   userName,
			"create_date": aws.ToTime(u.CreateDate),
			"has_console": hasConsole,
			"mfa_devices": mfaDevices,
			"access_keys": accessKeys,
		},
	}, nil
}

func userHasConsoleAccess(ctx context.Context, client *iam.Client, userName *string) (bool, error) {
	_, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: userName})
	if err == nil {
		return true, nil
	}
	var nfe *iamtypes.NoSuchEntityException
	if errors.As(err, &nfe) {
		return false, nil
	}
	return false, err
}

func listAccessKeys(ctx context.Context, client *iam.Client, userName *string) ([]map[string]any, error) {
	out := []map[string]any{}
	pager := iam.NewListAccessKeysPaginator(client, &iam.ListAccessKeysInput{UserName: userName})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, k := range page.AccessKeyMetadata {
			out = append(out, map[string]any{
				"access_key_id": aws.ToString(k.AccessKeyId),
				"status":        string(k.Status),
				"create_date":   aws.ToTime(k.CreateDate),
			})
		}
	}
	return out, nil
}

func listMFADevices(ctx context.Context, client *iam.Client, userName *string) ([]map[string]any, error) {
	out := []map[string]any{}
	pager := iam.NewListMFADevicesPaginator(client, &iam.ListMFADevicesInput{UserName: userName})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, m := range page.MFADevices {
			out = append(out, map[string]any{
				"serial_number": aws.ToString(m.SerialNumber),
				"enable_date":   aws.ToTime(m.EnableDate),
			})
		}
	}
	return out, nil
}
