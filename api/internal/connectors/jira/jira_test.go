package jira

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidate_HappyPath(t *testing.T) {
	in := `{
		"site_url": "https://forged-in-feathers.atlassian.net",
		"email": "ops@forgedinfeatherstechnology.com",
		"project_keys": ["SEC", "OPS"],
		"incident_labels": ["security", "incident"],
		"sla_window_days": 30,
		"attest_no_incidents": false,
		"api_token": "ATATT3xFfGF0_abcdefghijklmnop1234567890"
	}`
	cfg, sec, err := New().Validate(json.RawMessage(in))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sec == nil {
		t.Fatal("expected secret blob")
	}
	if strings.Contains(string(cfg), "ATATT3xFfGF0") || strings.Contains(string(cfg), "api_token") {
		t.Fatal("api_token leaked into public config")
	}
	var p PublicConfig
	if err := json.Unmarshal(cfg, &p); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	if p.SiteURL != "https://forged-in-feathers.atlassian.net" {
		t.Fatalf("site_url = %q", p.SiteURL)
	}
	if len(p.ProjectKeys) != 2 || p.ProjectKeys[0] != "SEC" {
		t.Fatalf("project_keys = %v", p.ProjectKeys)
	}
	if p.SLAWindowDays != 30 {
		t.Fatalf("sla_window_days = %d", p.SLAWindowDays)
	}
}

func TestValidate_NormalisesSiteURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"forged-in-feathers.atlassian.net", "https://forged-in-feathers.atlassian.net"},
		{"https://Acme.Atlassian.Net", "https://acme.atlassian.net"},
		{"https://acme.atlassian.net/", "https://acme.atlassian.net"},
		{"https://acme.atlassian.net/jira/projects", "https://acme.atlassian.net"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := normaliseSiteURL(tc.in)
			if err != nil {
				t.Fatalf("normaliseSiteURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidate_DefaultsLabelsAndSLA(t *testing.T) {
	in := `{
		"site_url": "https://acme.atlassian.net",
		"email": "ops@acme.com",
		"api_token": "ATATT3xFfGF0_abcdefghijklmnop"
	}`
	cfg, _, err := New().Validate(json.RawMessage(in))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	var p PublicConfig
	if err := json.Unmarshal(cfg, &p); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	if p.SLAWindowDays != defaultSLADays {
		t.Fatalf("sla = %d, want default %d", p.SLAWindowDays, defaultSLADays)
	}
	if len(p.IncidentLabels) != len(defaultLabels) {
		t.Fatalf("labels = %v, want defaults", p.IncidentLabels)
	}
}

func TestValidate_DeduplicatesProjectKeys(t *testing.T) {
	in := `{
		"site_url": "https://acme.atlassian.net",
		"email": "ops@acme.com",
		"project_keys": ["sec", "SEC", " OPS "],
		"api_token": "ATATT3xFfGF0_abcdefghijklmnop"
	}`
	cfg, _, err := New().Validate(json.RawMessage(in))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	var p PublicConfig
	if err := json.Unmarshal(cfg, &p); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	if len(p.ProjectKeys) != 2 {
		t.Fatalf("project_keys after dedupe = %v, want 2", p.ProjectKeys)
	}
}

func TestValidate_Rejects(t *testing.T) {
	base := func(overrides string) string {
		return `{"site_url":"https://acme.atlassian.net","email":"ops@acme.com","api_token":"ATATT3xFfGF0_abcdefghijklmnop"` + overrides + `}`
	}
	cases := []struct {
		name string
		body string
	}{
		{"empty site", `{"site_url":"","email":"ops@acme.com","api_token":"ATATT3xFfGF0_abcdefghijklmnop"}`},
		{"non-atlassian host", `{"site_url":"https://example.com","email":"ops@acme.com","api_token":"ATATT3xFfGF0_abcdefghijklmnop"}`},
		{"http instead of https", `{"site_url":"http://acme.atlassian.net","email":"ops@acme.com","api_token":"ATATT3xFfGF0_abcdefghijklmnop"}`},
		{"missing email", `{"site_url":"https://acme.atlassian.net","email":"","api_token":"ATATT3xFfGF0_abcdefghijklmnop"}`},
		{"short token", `{"site_url":"https://acme.atlassian.net","email":"ops@acme.com","api_token":"short"}`},
		{"invalid project key", base(`,"project_keys":["bad key!"]`)},
		{"sla too large", base(`,"sla_window_days":9999`)},
		{"malformed json", `{"site_url":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := (Connector{}).Validate(json.RawMessage(tc.body)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestBuildJQL(t *testing.T) {
	got := buildJQL([]string{"security", "incident"}, []string{"SEC", "OPS"}, "statusCategory = Done", `resolutiondate >= "2026-04-28"`)
	want := `labels in ("security", "incident") AND statusCategory = Done AND resolutiondate >= "2026-04-28" AND project in (SEC, OPS)`
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestBuildJQL_NoProjectScope(t *testing.T) {
	got := buildJQL([]string{"security"}, nil, "statusCategory != Done", `created <= "2026-04-28"`)
	want := `labels in ("security") AND statusCategory != Done AND created <= "2026-04-28"`
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}
