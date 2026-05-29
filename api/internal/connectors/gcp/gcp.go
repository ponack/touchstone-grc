// Package gcp implements the Touchstone connector for a Google
// Cloud project + (optionally) the surrounding Workspace / Cloud
// Identity tenant. Authentication: service account JSON key.
// Workload Identity Federation is planned once Touchstone publishes
// its own OIDC issuer (mirrors the Azure SP → WIF roadmap).
//
// Scope of this initial PR: Workspace user enumeration via the
// Admin SDK Directory API (domain-wide delegation required). Each
// user surfaces its 2-Step Verification enrollment / enforcement
// state — the signal CC6.1 needs. Cloud Storage, VPC firewall,
// Cloud Audit Logs, Security Command Center, Cloud SQL each land
// in follow-up PRs mirroring the Azure Phase 3 cadence.
package gcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ponack/touchstone/internal/connectors"
)

var (
	// GCP project IDs: 6–30 chars, lowercase letters/digits/hyphens,
	// must start with a letter, no trailing hyphen.
	projectIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

	// Workspace customer IDs are either the literal "my_customer"
	// (resolves to the caller's tenant) or a C-prefixed identifier
	// like "C01abc234".
	customerIDRE = regexp.MustCompile(`^(my_customer|C[a-z0-9]{6,16})$`)
)

// PublicConfig is what we persist in connectors.config and return on
// GET. No secret material lives here.
type PublicConfig struct {
	ProjectID            string `json:"project_id"`
	WorkspaceCustomerID  string `json:"workspace_customer_id,omitempty"`
	WorkspaceAdminEmail  string `json:"workspace_admin_email,omitempty"`
	ServiceAccountClient string `json:"service_account_client_email,omitempty"`
}

// Secret is the encrypted-at-rest service account JSON key (full
// contents) — used to mint OAuth access tokens and (when domain-
// wide delegation is configured) impersonate the workspace admin.
type Secret struct {
	ServiceAccountKeyJSON string `json:"service_account_key_json"`
}

// minimal subset of the SA key JSON we parse for validation.
type saKey struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
}

type Connector struct{}

func New() *Connector { return &Connector{} }

func (Connector) Kind() connectors.Kind { return connectors.KindGCP }

func (Connector) Validate(raw json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	var in struct {
		ProjectID             string `json:"project_id"`
		WorkspaceCustomerID   string `json:"workspace_customer_id"`
		WorkspaceAdminEmail   string `json:"workspace_admin_email"`
		ServiceAccountKeyJSON string `json:"service_account_key_json"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, nil, fmt.Errorf("invalid GCP config: %w", err)
	}

	if !projectIDRE.MatchString(in.ProjectID) {
		return nil, nil, errors.New("project_id is not a valid GCP project ID (6-30 chars, lowercase, must start with a letter)")
	}

	// SA key parse.
	keyBlob := strings.TrimSpace(in.ServiceAccountKeyJSON)
	if keyBlob == "" {
		return nil, nil, errors.New("service_account_key_json is required (paste the entire SA key file contents)")
	}
	var key saKey
	if err := json.Unmarshal([]byte(keyBlob), &key); err != nil {
		return nil, nil, fmt.Errorf("service_account_key_json is not valid JSON: %w", err)
	}
	if key.Type != "service_account" {
		return nil, nil, errors.New("service_account_key_json must be a service_account key (type field)")
	}
	if key.ClientEmail == "" || key.PrivateKey == "" {
		return nil, nil, errors.New("service_account_key_json missing client_email or private_key")
	}
	if !strings.Contains(key.PrivateKey, "BEGIN PRIVATE KEY") {
		return nil, nil, errors.New("service_account_key_json private_key does not look like a PEM block")
	}

	// Workspace fields are paired: both or neither.
	customer := strings.TrimSpace(in.WorkspaceCustomerID)
	admin := strings.TrimSpace(in.WorkspaceAdminEmail)
	if customer != "" || admin != "" {
		if customer == "" || admin == "" {
			return nil, nil, errors.New("workspace_customer_id and workspace_admin_email must be set together (or both omitted to skip Directory enumeration)")
		}
		if !customerIDRE.MatchString(customer) {
			return nil, nil, errors.New(`workspace_customer_id must be "my_customer" or a C-prefixed customer ID (e.g. "C01abc234")`)
		}
		if !strings.Contains(admin, "@") || len(admin) < 5 {
			return nil, nil, errors.New("workspace_admin_email must be the address of the Workspace admin the SA impersonates")
		}
	}

	cfg := PublicConfig{
		ProjectID:            in.ProjectID,
		WorkspaceCustomerID:  customer,
		WorkspaceAdminEmail:  admin,
		ServiceAccountClient: key.ClientEmail,
	}
	sec := Secret{ServiceAccountKeyJSON: keyBlob}

	cfgB, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, err
	}
	secB, err := json.Marshal(sec)
	if err != nil {
		return nil, nil, err
	}
	return cfgB, secB, nil
}
