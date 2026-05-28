// Package azure implements the Touchstone connector for an Azure
// tenant. Authentication: Service Principal (tenant_id, client_id,
// client_secret). Workload Identity Federation is planned for v0.4+
// once Touchstone publishes its own OIDC issuer.
//
// Scope of this initial PR: Azure AD user enumeration with MFA
// registration status via Microsoft Graph. Storage accounts, NSGs,
// Activity Log, Defender for Cloud, Azure SQL each land in
// follow-up PRs mirroring the AWS Phase 2 cadence.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/ponack/touchstone/internal/connectors"
)

// PublicConfig is what we persist in connectors.config and return on
// GET. No secret material lives here.
type PublicConfig struct {
	TenantID       string `json:"tenant_id"`
	SubscriptionID string `json:"subscription_id,omitempty"`
}

// Secret is the encrypted-at-rest Service Principal credential blob.
type Secret struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type Connector struct{}

func New() *Connector { return &Connector{} }

func (Connector) Kind() connectors.Kind { return connectors.KindAzure }

func (Connector) Validate(raw json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	var in struct {
		TenantID       string `json:"tenant_id"`
		SubscriptionID string `json:"subscription_id"`
		ClientID       string `json:"client_id"`
		ClientSecret   string `json:"client_secret"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, nil, fmt.Errorf("invalid Azure config: %w", err)
	}

	if !guidRE.MatchString(in.TenantID) {
		return nil, nil, errors.New("tenant_id must be a GUID")
	}
	if in.SubscriptionID != "" && !guidRE.MatchString(in.SubscriptionID) {
		return nil, nil, errors.New("subscription_id, if set, must be a GUID")
	}
	if !guidRE.MatchString(in.ClientID) {
		return nil, nil, errors.New("client_id must be a GUID")
	}
	if len(in.ClientSecret) < 8 {
		return nil, nil, errors.New("client_secret looks too short to be valid")
	}

	cfg := PublicConfig{
		TenantID:       in.TenantID,
		SubscriptionID: in.SubscriptionID,
	}
	sec := Secret{
		ClientID:     in.ClientID,
		ClientSecret: in.ClientSecret,
	}

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

func (Connector) Scan(ctx context.Context, cfgRaw, secretRaw json.RawMessage) (*connectors.ScanResult, error) {
	var cfg PublicConfig
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if len(secretRaw) == 0 {
		return nil, errors.New("azure scan: missing secret")
	}
	var sec Secret
	if err := json.Unmarshal(secretRaw, &sec); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}

	res := &connectors.ScanResult{}

	adRes, err := scanAD(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, adRes...)

	storageRes, err := scanStorage(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, storageRes...)

	return res, nil
}

// GUIDs are the canonical Azure identifier shape.
var guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
