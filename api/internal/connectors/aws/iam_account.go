package aws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

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

	support, err := buildSupportAccessSummary(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("iam:ListEntitiesForPolicy(AWSSupportAccess): %w", err)
	}
	out = append(out, support)

	certs, err := listServerCertificates(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("iam:ListServerCertificates: %w", err)
	}
	out = append(out, certs...)

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

	// CIS 1.6 needs to know whether root's MFA is virtual (fails) or
	// hardware (passes). ListVirtualMFADevices.User points at the
	// associated principal; root's ARN ends with ":root". When the
	// root user shows up in the list, root MFA is virtual.
	rootVirtualMFA, err := rootHasVirtualMFA(ctx, client)
	if err != nil {
		return connectors.Resource{}, fmt.Errorf("iam:ListVirtualMFADevices: %w", err)
	}

	return connectors.Resource{
		Type: "aws.iam.account_summary",
		ID:   "aws-iam://account/summary",
		Attrs: map[string]any{
			"root_access_keys_present":   rootAccessKeys > 0,
			"root_mfa_enabled":           rootMFAEnabled == 1,
			"root_mfa_virtual":           rootVirtualMFA,
			"root_signing_certs_present": rootSigningCerts > 0,
		},
	}, nil
}

// rootHasVirtualMFA scans the account's virtual MFA devices and
// returns true when one is bound to the root user. CIS 1.6 reads
// the inverse — "is hardware MFA in use" — but checking for
// virtual-on-root is the directly observable signal.
func rootHasVirtualMFA(ctx context.Context, client *iam.Client) (bool, error) {
	pager := iam.NewListVirtualMFADevicesPaginator(client, &iam.ListVirtualMFADevicesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return false, err
		}
		for _, dev := range page.VirtualMFADevices {
			if dev.User == nil {
				continue
			}
			arn := aws.ToString(dev.User.Arn)
			if strings.HasSuffix(arn, ":root") {
				return true, nil
			}
		}
	}
	return false, nil
}

// listServerCertificates emits one aws.iam.server_certificate
// resource per IAM-uploaded SSL/TLS cert. CIS 1.19 fails when any
// cert is past expiration; tracked separately from ACM, which has
// its own certificate inventory.
func listServerCertificates(ctx context.Context, client *iam.Client) ([]connectors.Resource, error) {
	out := []connectors.Resource{}
	pager := iam.NewListServerCertificatesPaginator(client, &iam.ListServerCertificatesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range page.ServerCertificateMetadataList {
			attrs := map[string]any{
				"server_certificate_name": aws.ToString(c.ServerCertificateName),
				"path":                    aws.ToString(c.Path),
				"upload_date":             aws.ToTime(c.UploadDate),
			}
			if c.Expiration != nil {
				attrs["expiration"] = aws.ToTime(c.Expiration)
			} else {
				attrs["expiration"] = nil
			}
			out = append(out, connectors.Resource{
				Type:  "aws.iam.server_certificate",
				ID:    aws.ToString(c.Arn),
				Attrs: attrs,
			})
		}
	}
	return out, nil
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

// supportAccessPolicyARN is the AWS managed policy that grants the
// minimum permissions needed to open AWS Support cases. CIS 1.17
// requires a principal somewhere in the account to hold this
// policy so support tickets can actually be filed.
const supportAccessPolicyARN = "arn:aws:iam::aws:policy/AWSSupportAccess"

// buildSupportAccessSummary counts the principals attached to the
// AWSSupportAccess managed policy. A count of zero is the CIS 1.17
// failure signal; the rego inspects the booleans + counts directly
// rather than parsing principal lists.
func buildSupportAccessSummary(ctx context.Context, client *iam.Client) (connectors.Resource, error) {
	users := 0
	groups := 0
	roles := 0
	pager := iam.NewListEntitiesForPolicyPaginator(client, &iam.ListEntitiesForPolicyInput{
		PolicyArn: aws.String(supportAccessPolicyARN),
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return connectors.Resource{}, err
		}
		users += len(page.PolicyUsers)
		groups += len(page.PolicyGroups)
		roles += len(page.PolicyRoles)
	}
	return connectors.Resource{
		Type: "aws.iam.support_access_summary",
		ID:   "aws-iam://account/support-access",
		Attrs: map[string]any{
			"policy_arn":             supportAccessPolicyARN,
			"attached_users_count":   users,
			"attached_groups_count":  groups,
			"attached_roles_count":   roles,
			"total_attachment_count": users + groups + roles,
		},
	}, nil
}
