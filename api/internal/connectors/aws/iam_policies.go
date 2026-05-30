package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanIAMPolicies enumerates customer-managed IAM policies and, for
// each, surfaces (a) the current attachment count and (b) whether
// its default-version document grants full administrative
// privileges ({"Effect":"Allow","Action":"*","Resource":"*"}).
// CIS 1.16 fails when both are true for any policy.
//
// AWS-managed policies (AdministratorAccess and friends) are out of
// scope here — CIS targets customer-defined admin policies that
// should be retired, not the AWS-managed ones.
func scanIAMPolicies(ctx context.Context, awsCfg aws.Config) ([]connectors.Resource, error) {
	client := iam.NewFromConfig(awsCfg)
	out := []connectors.Resource{}

	pager := iam.NewListPoliciesPaginator(client, &iam.ListPoliciesInput{
		Scope: iamtypes.PolicyScopeTypeLocal,
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam:ListPolicies(Local): %w", err)
		}
		for _, p := range page.Policies {
			res, err := buildCustomerManagedPolicyResource(ctx, client, p)
			if err != nil {
				slog.Warn("iam policy enrichment failed", "policy", aws.ToString(p.PolicyName), "err", err)
				continue
			}
			out = append(out, res)
		}
	}
	return out, nil
}

func buildCustomerManagedPolicyResource(ctx context.Context, client *iam.Client, p iamtypes.Policy) (connectors.Resource, error) {
	arn := aws.ToString(p.Arn)
	attachmentCount := 0
	if p.AttachmentCount != nil {
		attachmentCount = int(*p.AttachmentCount)
	}

	isAdmin, err := policyDocumentAllowsAdmin(ctx, client, arn, aws.ToString(p.DefaultVersionId))
	if err != nil {
		return connectors.Resource{}, fmt.Errorf("get policy version: %w", err)
	}

	return connectors.Resource{
		Type: "aws.iam.customer_managed_policy",
		ID:   arn,
		Attrs: map[string]any{
			"policy_name":      aws.ToString(p.PolicyName),
			"arn":              arn,
			"default_version":  aws.ToString(p.DefaultVersionId),
			"attachment_count": attachmentCount,
			"is_admin":         isAdmin,
		},
	}, nil
}

// policyDocumentAllowsAdmin fetches the default version of a policy
// and inspects its document for any "*:*" admin statement.
func policyDocumentAllowsAdmin(ctx context.Context, client *iam.Client, arn, versionID string) (bool, error) {
	resp, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(arn),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return false, err
	}
	if resp.PolicyVersion == nil || resp.PolicyVersion.Document == nil {
		return false, nil
	}

	// AWS returns the document URL-encoded; decode once before
	// parsing.
	raw, err := url.QueryUnescape(aws.ToString(resp.PolicyVersion.Document))
	if err != nil {
		return false, fmt.Errorf("url-decode policy: %w", err)
	}
	return documentAllowsAdmin([]byte(raw))
}

// documentAllowsAdmin returns true when the IAM policy document
// contains any statement where Effect=Allow and both Action and
// Resource include the literal "*". Action and Resource may each
// be a single string or a string array.
func documentAllowsAdmin(doc []byte) (bool, error) {
	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		return false, fmt.Errorf("parse policy doc: %w", err)
	}

	// Statement may be either an object or an array of objects.
	var statements []struct {
		Effect   string          `json:"Effect"`
		Action   json.RawMessage `json:"Action"`
		Resource json.RawMessage `json:"Resource"`
	}
	if len(parsed.Statement) > 0 && parsed.Statement[0] == '[' {
		if err := json.Unmarshal(parsed.Statement, &statements); err != nil {
			return false, fmt.Errorf("parse statement array: %w", err)
		}
	} else {
		var single struct {
			Effect   string          `json:"Effect"`
			Action   json.RawMessage `json:"Action"`
			Resource json.RawMessage `json:"Resource"`
		}
		if err := json.Unmarshal(parsed.Statement, &single); err != nil {
			return false, fmt.Errorf("parse statement object: %w", err)
		}
		statements = append(statements, single)
	}

	for _, s := range statements {
		if s.Effect != "Allow" {
			continue
		}
		if rawIncludesStar(s.Action) && rawIncludesStar(s.Resource) {
			return true, nil
		}
	}
	return false, nil
}

// rawIncludesStar reports whether a JSON-encoded value (string or
// string array) contains the literal "*".
func rawIncludesStar(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == "*"
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err == nil {
		for _, v := range multi {
			if v == "*" {
				return true
			}
		}
	}
	return false
}
