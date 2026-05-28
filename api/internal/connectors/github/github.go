// Package github implements the Touchstone connector for a GitHub
// organization. Authentication: Personal Access Token (classic or
// fine-grained) with the read:org scope. GitHub App / OAuth flows
// are planned for a follow-up.
//
// Scope of this initial PR: org-level 2FA requirement + the list of
// members who have 2FA disabled. CC6.2 (new user access
// provisioning) evaluates the pragmatic v0 signal — "is MFA
// enforced". Strict provisioning ticket linkage extends this in
// a follow-up.
package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/ponack/touchstone/internal/connectors"
)

// PublicConfig is what we persist in connectors.config and return on
// GET. No secret material lives here.
type PublicConfig struct {
	Org string `json:"org"`
}

// Secret is the encrypted-at-rest PAT.
type Secret struct {
	AccessToken string `json:"access_token"`
}

type Connector struct{}

func New() *Connector { return &Connector{} }

func (Connector) Kind() connectors.Kind { return connectors.KindGitHub }

func (Connector) Validate(raw json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	var in struct {
		Org         string `json:"org"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, nil, fmt.Errorf("invalid GitHub config: %w", err)
	}

	if !orgRE.MatchString(in.Org) {
		return nil, nil, errors.New(`org must be a valid GitHub org login (alphanumeric + dashes, 1-39 chars, no leading dash)`)
	}
	if len(in.AccessToken) < 20 {
		return nil, nil, errors.New("access_token looks too short to be a GitHub PAT")
	}

	cfg := PublicConfig{Org: in.Org}
	sec := Secret{AccessToken: in.AccessToken}

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

// GitHub org logins: 1-39 chars, alphanumeric + single dashes, no
// leading or trailing dash. Mirrors GitHub's own restrictions.
var orgRE = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?:[a-zA-Z0-9])){0,38}$`)
