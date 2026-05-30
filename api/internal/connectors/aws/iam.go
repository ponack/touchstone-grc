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

	attachedCount, inlineCount, err := userDirectPolicyCounts(ctx, client, u.UserName)
	if err != nil {
		return connectors.Resource{}, fmt.Errorf("user policies: %w", err)
	}

	// password_last_used is the freshness signal CIS 1.12 needs for
	// console credentials. ListUsers already returns it on the User
	// struct, so no extra API call. Nil means "never used" — a real
	// signal in its own right.
	var passwordLastUsed any
	if u.PasswordLastUsed != nil {
		passwordLastUsed = aws.ToTime(u.PasswordLastUsed)
	}

	return connectors.Resource{
		Type: "aws.iam.user",
		ID:   aws.ToString(u.Arn),
		Attrs: map[string]any{
			"user_name":               userName,
			"create_date":             aws.ToTime(u.CreateDate),
			"has_console":             hasConsole,
			"password_last_used":      passwordLastUsed,
			"mfa_devices":             mfaDevices,
			"access_keys":             accessKeys,
			"attached_policies_count": attachedCount,
			"inline_policies_count":   inlineCount,
		},
	}, nil
}

// userDirectPolicyCounts returns how many managed and inline policies
// are attached directly to the user (i.e. not via a group). CIS 1.15
// expects both counts to be zero — permissions should flow only
// through group membership.
func userDirectPolicyCounts(ctx context.Context, client *iam.Client, userName *string) (int, int, error) {
	attached := 0
	attachedPager := iam.NewListAttachedUserPoliciesPaginator(client, &iam.ListAttachedUserPoliciesInput{UserName: userName})
	for attachedPager.HasMorePages() {
		page, err := attachedPager.NextPage(ctx)
		if err != nil {
			return 0, 0, err
		}
		attached += len(page.AttachedPolicies)
	}

	inline := 0
	inlinePager := iam.NewListUserPoliciesPaginator(client, &iam.ListUserPoliciesInput{UserName: userName})
	for inlinePager.HasMorePages() {
		page, err := inlinePager.NextPage(ctx)
		if err != nil {
			return 0, 0, err
		}
		inline += len(page.PolicyNames)
	}
	return attached, inline, nil
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
			lastUsed, err := accessKeyLastUsed(ctx, client, k.AccessKeyId)
			if err != nil {
				slog.Warn("iam access key last-used lookup failed", "key", aws.ToString(k.AccessKeyId), "err", err)
				// Carry on — the rego treats nil last_used_date the
				// same as "never used", which is the right semantic
				// when AWS can't tell us either way.
				lastUsed = nil
			}
			out = append(out, map[string]any{
				"access_key_id":  aws.ToString(k.AccessKeyId),
				"status":         string(k.Status),
				"create_date":    aws.ToTime(k.CreateDate),
				"last_used_date": lastUsed,
			})
		}
	}
	return out, nil
}

// accessKeyLastUsed returns the LastUsedDate for an access key, or
// nil when AWS reports "key was never used". The SDK signals never-
// used by returning a zero LastUsedDate inside a populated
// AccessKeyLastUsed struct; we collapse that into nil so the rego
// rule's "no last-used timestamp" branch fires.
func accessKeyLastUsed(ctx context.Context, client *iam.Client, accessKeyID *string) (any, error) {
	resp, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: accessKeyID})
	if err != nil {
		return nil, err
	}
	if resp.AccessKeyLastUsed == nil || resp.AccessKeyLastUsed.LastUsedDate == nil {
		return nil, nil
	}
	return aws.ToTime(resp.AccessKeyLastUsed.LastUsedDate), nil
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
