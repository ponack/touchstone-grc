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

// scanIAMAccount enumerates two account-level IAM surfaces that CIS
// AWS Benchmarks v1.5 rules in Section 1 (IAM) evaluate against:
//
//   - GetAccountSummary       — root MFA + account-wide MFA + root access
//     key counts. Powers CIS 1.4 and 1.5.
//   - GetAccountPasswordPolicy — length / reuse / rotation knobs that
//     CIS 1.8 and 1.9 check.
//
// Both calls produce one resource each. Each scan is independent —
// if password policy is unconfigured, GetAccountPasswordPolicy
// returns NoSuchEntity, which we surface as an attrs-only "no
// password policy set" resource so the rego can fail it cleanly.
func scanIAMAccount(ctx context.Context, awsCfg aws.Config) ([]connectors.Resource, error) {
	client := iam.NewFromConfig(awsCfg)
	out := make([]connectors.Resource, 0, 2)

	summary, err := buildAccountSummary(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("iam:GetAccountSummary: %w", err)
	}
	out = append(out, summary)

	policy, err := buildPasswordPolicy(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("iam:GetAccountPasswordPolicy: %w", err)
	}
	out = append(out, policy)

	slog.Info("iam account scan complete", "resources", len(out))
	return out, nil
}

func buildAccountSummary(ctx context.Context, client *iam.Client) (connectors.Resource, error) {
	resp, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return connectors.Resource{}, err
	}
	// SummaryMap returns int32 values keyed by well-known names.
	rootAccessKeys := int(resp.SummaryMap["AccountAccessKeysPresent"])
	rootMFAEnabled := int(resp.SummaryMap["AccountMFAEnabled"])
	rootSigningCerts := int(resp.SummaryMap["AccountSigningCertificatesPresent"])

	return connectors.Resource{
		Type: "aws.iam.account_summary",
		ID:   "aws-iam://account/summary",
		Attrs: map[string]any{
			"root_access_keys_present":   rootAccessKeys > 0,
			"root_mfa_enabled":           rootMFAEnabled == 1,
			"root_signing_certs_present": rootSigningCerts > 0,
		},
	}, nil
}

func buildPasswordPolicy(ctx context.Context, client *iam.Client) (connectors.Resource, error) {
	resp, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		// IAM returns NoSuchEntity when no password policy has been
		// configured. Emit a resource marked "not configured" so the
		// CIS rule can fail without ambiguity.
		var nse *iamtypes.NoSuchEntityException
		if errors.As(err, &nse) {
			return connectors.Resource{
				Type: "aws.iam.password_policy",
				ID:   "aws-iam://account/password-policy",
				Attrs: map[string]any{
					"configured": false,
				},
			}, nil
		}
		return connectors.Resource{}, err
	}

	p := resp.PasswordPolicy
	attrs := map[string]any{
		"configured":                     true,
		"minimum_password_length":        intPtr(p.MinimumPasswordLength),
		"require_symbols":                p.RequireSymbols,
		"require_numbers":                p.RequireNumbers,
		"require_uppercase_characters":   p.RequireUppercaseCharacters,
		"require_lowercase_characters":   p.RequireLowercaseCharacters,
		"allow_users_to_change_password": p.AllowUsersToChangePassword,
		"expire_passwords":               p.ExpirePasswords,
		"max_password_age":               intPtr(p.MaxPasswordAge),
		"password_reuse_prevention":      intPtr(p.PasswordReusePrevention),
		"hard_expiry":                    aws.ToBool(p.HardExpiry),
	}
	return connectors.Resource{
		Type:  "aws.iam.password_policy",
		ID:    "aws-iam://account/password-policy",
		Attrs: attrs,
	}, nil
}

// intPtr returns the int value of an SDK *int32 field, or 0 when nil.
// rego treats 0 cleanly in numeric comparisons — "absent" doesn't
// need to be a separate sentinel.
func intPtr(p *int32) int {
	if p == nil {
		return 0
	}
	return int(*p)
}
