package linear

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidate_HappyPath(t *testing.T) {
	in := `{
		"workspace_name": "Forged in Feathers",
		"incident_labels": ["security", "incident"],
		"sla_window_days": 30,
		"attest_no_incidents": false,
		"api_key": "lin_api_abcdefghijklmnop1234567890ABCDEF"
	}`
	cfg, sec, err := New().Validate(json.RawMessage(in))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sec == nil {
		t.Fatal("expected secret blob")
	}
	if strings.Contains(string(cfg), "lin_api_") || strings.Contains(string(cfg), "api_key") {
		t.Fatal("api_key leaked into public config")
	}
	var p PublicConfig
	if err := json.Unmarshal(cfg, &p); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	if p.WorkspaceName != "Forged in Feathers" {
		t.Fatalf("workspace_name not preserved: %q", p.WorkspaceName)
	}
	if p.SLAWindowDays != 30 {
		t.Fatalf("sla_window_days = %d, want 30", p.SLAWindowDays)
	}
	if len(p.IncidentLabels) != 2 {
		t.Fatalf("incident_labels = %v, want 2 entries", p.IncidentLabels)
	}
}

func TestValidate_DefaultsLabelsAndSLA(t *testing.T) {
	in := `{
		"workspace_name": "Acme",
		"api_key": "lin_api_abcdefghijklmnop1234567890ABCDEF"
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
		t.Fatalf("sla_window_days = %d, want default %d", p.SLAWindowDays, defaultSLADays)
	}
	if len(p.IncidentLabels) != len(defaultLabels) {
		t.Fatalf("incident_labels = %v, want defaults", p.IncidentLabels)
	}
}

func TestValidate_DeduplicatesLabels(t *testing.T) {
	in := `{
		"workspace_name": "Acme",
		"incident_labels": ["Security", "security", " incident ", "incident"],
		"api_key": "lin_api_abcdefghijklmnop1234567890ABCDEF"
	}`
	cfg, _, err := New().Validate(json.RawMessage(in))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	var p PublicConfig
	if err := json.Unmarshal(cfg, &p); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	if len(p.IncidentLabels) != 2 {
		t.Fatalf("incident_labels after dedupe = %v, want 2", p.IncidentLabels)
	}
}

func TestValidate_Rejects(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty workspace", `{"workspace_name": "", "api_key": "lin_api_abcdefghijklmnop1234567890ABCDEF"}`},
		{"short api key", `{"workspace_name": "Acme", "api_key": "short"}`},
		{"sla too large", `{"workspace_name": "Acme", "sla_window_days": 9999, "api_key": "lin_api_abcdefghijklmnop1234567890ABCDEF"}`},
		{"sla negative", `{"workspace_name": "Acme", "sla_window_days": -5, "api_key": "lin_api_abcdefghijklmnop1234567890ABCDEF"}`},
		{"malformed json", `{"workspace_name":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := (Connector{}).Validate(json.RawMessage(tc.body)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}
