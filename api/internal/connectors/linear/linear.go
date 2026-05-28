// Package linear implements the Touchstone connector for a Linear
// workspace. Authentication: a personal API key (lin_api_...) scoped
// to the workspace. Linear API keys are workspace-scoped, so one
// connector instance covers exactly one workspace.
//
// Scope of this initial PR: enumerate Linear issues labelled
// "security" / "incident" (configurable) and bucket them into closed
// inside an SLA window vs. open longer than the SLA window. CC7.4
// (incident response) evaluates a pragmatic v0 signal — proof that
// the operator is actually using a ticket workflow for security
// incidents, or an explicit "no incidents this period" attestation.
package linear

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ponack/touchstone/internal/connectors"
)

// Defaults applied when the inbound config leaves a field empty.
var (
	defaultLabels    = []string{"security", "incident"}
	defaultSLADays   = 30
	maxSLADays       = 365
	minAPIKeyLength  = 30
	maxLabelEntries  = 32
	maxWorkspaceName = 128
)

// PublicConfig is what we persist in connectors.config and return on
// GET. No secret material lives here.
type PublicConfig struct {
	WorkspaceName     string   `json:"workspace_name"`
	IncidentLabels    []string `json:"incident_labels"`
	SLAWindowDays     int      `json:"sla_window_days"`
	AttestNoIncidents bool     `json:"attest_no_incidents"`
}

// Secret is the encrypted-at-rest Linear API key.
type Secret struct {
	APIKey string `json:"api_key"`
}

type Connector struct{}

func New() *Connector { return &Connector{} }

func (Connector) Kind() connectors.Kind { return connectors.KindLinear }

func (Connector) Validate(raw json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	var in struct {
		WorkspaceName     string   `json:"workspace_name"`
		IncidentLabels    []string `json:"incident_labels"`
		SLAWindowDays     int      `json:"sla_window_days"`
		AttestNoIncidents bool     `json:"attest_no_incidents"`
		APIKey            string   `json:"api_key"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, nil, fmt.Errorf("invalid Linear config: %w", err)
	}

	name := strings.TrimSpace(in.WorkspaceName)
	if name == "" {
		return nil, nil, errors.New("workspace_name is required")
	}
	if len(name) > maxWorkspaceName {
		return nil, nil, fmt.Errorf("workspace_name longer than %d chars", maxWorkspaceName)
	}

	labels := normaliseLabels(in.IncidentLabels)
	if len(labels) == 0 {
		labels = append(labels, defaultLabels...)
	}
	if len(labels) > maxLabelEntries {
		return nil, nil, fmt.Errorf("incident_labels has more than %d entries", maxLabelEntries)
	}

	sla := in.SLAWindowDays
	if sla == 0 {
		sla = defaultSLADays
	}
	if sla < 1 || sla > maxSLADays {
		return nil, nil, fmt.Errorf("sla_window_days must be between 1 and %d", maxSLADays)
	}

	if len(in.APIKey) < minAPIKeyLength {
		return nil, nil, errors.New("api_key looks too short to be a Linear personal API key")
	}

	cfg := PublicConfig{
		WorkspaceName:     name,
		IncidentLabels:    labels,
		SLAWindowDays:     sla,
		AttestNoIncidents: in.AttestNoIncidents,
	}
	sec := Secret{APIKey: in.APIKey}

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

func normaliseLabels(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		key := strings.ToLower(s)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out
}
