// Package jira implements the Touchstone connector for an Atlassian
// Jira Cloud site. Authentication: email + API token (Basic auth).
// Server / Data Center are out of scope for v0.
//
// Scope of this initial PR: enumerate Jira issues labelled
// "security" / "incident" (configurable) and bucket them into
// closed-inside-SLA-window vs. open-past-SLA-window. CC7.4 is
// already real for Linear; this PR makes Jira a parallel source so
// either ticketing system satisfies the control.
package jira

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ponack/touchstone/internal/connectors"
)

var (
	defaultLabels       = []string{"security", "incident"}
	defaultSLADays      = 30
	maxSLADays          = 365
	minAPITokenLength   = 16
	maxLabelEntries     = 32
	maxProjectKeyChars  = 24
	maxProjectKeyCount  = 32
	projectKeyRE        = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,23}$`)
	atlassianSiteSuffix = ".atlassian.net"
)

// PublicConfig is what we persist in connectors.config and return on
// GET. No secret material lives here.
type PublicConfig struct {
	SiteURL           string   `json:"site_url"`
	Email             string   `json:"email"`
	ProjectKeys       []string `json:"project_keys,omitempty"`
	IncidentLabels    []string `json:"incident_labels"`
	SLAWindowDays     int      `json:"sla_window_days"`
	AttestNoIncidents bool     `json:"attest_no_incidents"`
}

// Secret is the encrypted-at-rest API token.
type Secret struct {
	APIToken string `json:"api_token"`
}

type Connector struct{}

func New() *Connector { return &Connector{} }

func (Connector) Kind() connectors.Kind { return connectors.KindJira }

func (Connector) Validate(raw json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	var in struct {
		SiteURL           string   `json:"site_url"`
		Email             string   `json:"email"`
		ProjectKeys       []string `json:"project_keys"`
		IncidentLabels    []string `json:"incident_labels"`
		SLAWindowDays     int      `json:"sla_window_days"`
		AttestNoIncidents bool     `json:"attest_no_incidents"`
		APIToken          string   `json:"api_token"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, nil, fmt.Errorf("invalid Jira config: %w", err)
	}

	site, err := normaliseSiteURL(in.SiteURL)
	if err != nil {
		return nil, nil, err
	}

	email := strings.TrimSpace(in.Email)
	if !strings.Contains(email, "@") || len(email) < 5 {
		return nil, nil, errors.New("email must be the Atlassian account email used to mint the API token")
	}

	keys, err := normaliseProjectKeys(in.ProjectKeys)
	if err != nil {
		return nil, nil, err
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

	if len(in.APIToken) < minAPITokenLength {
		return nil, nil, errors.New("api_token looks too short to be a Jira Cloud API token")
	}

	cfg := PublicConfig{
		SiteURL:           site,
		Email:             email,
		ProjectKeys:       keys,
		IncidentLabels:    labels,
		SLAWindowDays:     sla,
		AttestNoIncidents: in.AttestNoIncidents,
	}
	sec := Secret{APIToken: in.APIToken}

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

func normaliseSiteURL(in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", errors.New("site_url is required (e.g. https://acme.atlassian.net)")
	}
	if !strings.HasPrefix(in, "http://") && !strings.HasPrefix(in, "https://") {
		in = "https://" + in
	}
	u, err := url.Parse(in)
	if err != nil || u.Host == "" {
		return "", errors.New("site_url is not a valid URL")
	}
	if u.Scheme != "https" {
		return "", errors.New("site_url must use https")
	}
	if !strings.HasSuffix(strings.ToLower(u.Host), atlassianSiteSuffix) {
		return "", fmt.Errorf("site_url host must end in %s (Atlassian Cloud)", atlassianSiteSuffix)
	}
	return "https://" + strings.ToLower(u.Host), nil
}

func normaliseProjectKeys(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, k := range in {
		k = strings.ToUpper(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		if len(k) > maxProjectKeyChars || !projectKeyRE.MatchString(k) {
			return nil, fmt.Errorf("project key %q is not a valid Jira key (uppercase, alphanumeric + underscore, ≤%d chars)", k, maxProjectKeyChars)
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	if len(out) > maxProjectKeyCount {
		return nil, fmt.Errorf("project_keys has more than %d entries", maxProjectKeyCount)
	}
	return out, nil
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
