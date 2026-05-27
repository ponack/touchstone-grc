// Package aws implements the Touchstone connector for an AWS account.
//
// This package only ships the configuration surface for now: shape
// validation + credential extraction. Actual resource enumeration
// (IAM, S3, EC2 SGs, CloudTrail, GuardDuty, Config, KMS, RDS) lands
// in a follow-up PR with the scan workflow.
//
// Two auth methods are supported:
//
//   - "role"  Touchstone assumes a customer-controlled IAM role via
//     STS. The customer's role trust policy gates access; we
//     never hold long-lived credentials. Recommended.
//   - "key"   Long-lived IAM access key + secret. The key/secret pair
//     is encrypted with TOUCHSTONE_SECRET_KEY before it hits
//     the DB. Use only when the deployment can't grant a role.
package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ponack/touchstone/internal/connectors"
)

// PublicConfig is what we persist in connectors.config and return on
// GET. No secret material lives here.
type PublicConfig struct {
	AccountID  string   `json:"account_id"`
	Regions    []string `json:"regions"`
	AuthMethod string   `json:"auth_method"` // "role" | "key"
	RoleARN    string   `json:"role_arn,omitempty"`
	ExternalID string   `json:"external_id,omitempty"`
}

// Secret is the encrypted-at-rest credential blob (only used when
// AuthMethod == "key").
type Secret struct {
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
}

type Connector struct{}

func New() *Connector { return &Connector{} }

func (Connector) Kind() connectors.Kind { return connectors.KindAWS }

// Scan enumerates the configured AWS account. PR D.2 covers IAM only;
// S3, EC2, CloudTrail, GuardDuty, Config, KMS, RDS arrive in
// follow-ups as the SOC 2 rego policies that need them are written.
func (Connector) Scan(ctx context.Context, cfgRaw, secretRaw json.RawMessage) (*connectors.ScanResult, error) {
	var cfg PublicConfig
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	var sec Secret
	if cfg.AuthMethod == "key" {
		if len(secretRaw) == 0 {
			return nil, errors.New("aws scan: auth_method=key requires a secret")
		}
		if err := json.Unmarshal(secretRaw, &sec); err != nil {
			return nil, fmt.Errorf("decode secret: %w", err)
		}
	}

	awsCfg, err := buildAWSConfig(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}

	res := &connectors.ScanResult{}

	iamRes, err := scanIAM(ctx, awsCfg)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, iamRes...)

	s3Res, err := scanS3(ctx, awsCfg)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, s3Res...)

	ec2Res, err := scanEC2(ctx, awsCfg, cfg.Regions)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, ec2Res...)

	ctRes, err := scanCloudTrail(ctx, awsCfg, cfg.Regions)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, ctRes...)

	gdRes, err := scanGuardDuty(ctx, awsCfg, cfg.Regions)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, gdRes...)

	shRes, err := scanSecurityHub(ctx, awsCfg, cfg.Regions)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, shRes...)

	return res, nil
}

func (Connector) Validate(raw json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	var in struct {
		AccountID       string   `json:"account_id"`
		Regions         []string `json:"regions"`
		AuthMethod      string   `json:"auth_method"`
		RoleARN         string   `json:"role_arn"`
		ExternalID      string   `json:"external_id"`
		AccessKeyID     string   `json:"access_key_id"`
		SecretAccessKey string   `json:"secret_access_key"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, nil, fmt.Errorf("invalid AWS config: %w", err)
	}

	if !accountIDRE.MatchString(in.AccountID) {
		return nil, nil, errors.New("account_id must be exactly 12 digits")
	}
	if len(in.Regions) == 0 {
		return nil, nil, errors.New("at least one region is required")
	}
	for _, r := range in.Regions {
		if !regionRE.MatchString(r) {
			return nil, nil, fmt.Errorf("invalid region: %q", r)
		}
	}

	cfg := PublicConfig{
		AccountID:  in.AccountID,
		Regions:    dedupe(in.Regions),
		AuthMethod: strings.ToLower(strings.TrimSpace(in.AuthMethod)),
	}
	var sec Secret
	switch cfg.AuthMethod {
	case "role":
		if !roleARNRE.MatchString(in.RoleARN) {
			return nil, nil, errors.New("role_arn must look like arn:aws:iam::<12-digit account>:role/<name>")
		}
		cfg.RoleARN = in.RoleARN
		cfg.ExternalID = in.ExternalID
	case "key":
		if !accessKeyRE.MatchString(in.AccessKeyID) {
			return nil, nil, errors.New("access_key_id must be 16-128 chars matching ^[A-Z0-9]+$")
		}
		if len(in.SecretAccessKey) < 16 {
			return nil, nil, errors.New("secret_access_key looks too short to be valid")
		}
		sec = Secret{AccessKeyID: in.AccessKeyID, SecretAccessKey: in.SecretAccessKey}
	default:
		return nil, nil, errors.New(`auth_method must be "role" or "key"`)
	}

	cfgB, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, err
	}
	var secB json.RawMessage
	if cfg.AuthMethod == "key" {
		b, err := json.Marshal(sec)
		if err != nil {
			return nil, nil, err
		}
		secB = b
	}
	return cfgB, secB, nil
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

var (
	accountIDRE = regexp.MustCompile(`^[0-9]{12}$`)
	regionRE    = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]+$`)
	roleARNRE   = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$`)
	accessKeyRE = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
)
