package gcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// A real-looking SA key blob: type/client_email/private_key shaped
// like the real thing, with a syntactically valid PEM block. The
// private key body is junk — Validate doesn't try to decrypt it.
const fakeSAKey = `{
  "type": "service_account",
  "project_id": "forged-in-feathers-touchstone",
  "private_key_id": "abc123",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----\n",
  "client_email": "touchstone-scanner@forged-in-feathers-touchstone.iam.gserviceaccount.com",
  "client_id": "111222333444555666777"
}`

func TestValidate_HappyPath(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"project_id":               "forged-in-feathers-touchstone",
		"workspace_customer_id":    "my_customer",
		"workspace_admin_email":    "ops@forgedinfeatherstechnology.com",
		"service_account_key_json": fakeSAKey,
	})
	cfg, sec, err := New().Validate(body)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sec == nil {
		t.Fatal("expected secret blob")
	}
	if strings.Contains(string(cfg), "BEGIN PRIVATE KEY") {
		t.Fatal("private key leaked into public config")
	}
	var p PublicConfig
	if err := json.Unmarshal(cfg, &p); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	if p.ProjectID != "forged-in-feathers-touchstone" {
		t.Fatalf("project_id = %q", p.ProjectID)
	}
	if p.ServiceAccountClient == "" {
		t.Fatal("expected ServiceAccountClient populated from SA JSON")
	}
}

func TestValidate_WorkspaceOptional(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"project_id":               "acme-prod-001",
		"service_account_key_json": fakeSAKey,
	})
	cfg, _, err := New().Validate(body)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	var p PublicConfig
	if err := json.Unmarshal(cfg, &p); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	if p.WorkspaceCustomerID != "" || p.WorkspaceAdminEmail != "" {
		t.Fatalf("workspace fields should be empty when omitted: %+v", p)
	}
}

func TestValidate_Rejects(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing project", map[string]any{"service_account_key_json": fakeSAKey}},
		{"invalid project format", map[string]any{"project_id": "BadProject", "service_account_key_json": fakeSAKey}},
		{"empty SA key", map[string]any{"project_id": "acme-prod-001", "service_account_key_json": ""}},
		{"malformed SA JSON", map[string]any{"project_id": "acme-prod-001", "service_account_key_json": "{not json"}},
		{"wrong SA type", map[string]any{"project_id": "acme-prod-001", "service_account_key_json": `{"type":"user_managed","client_email":"x@y","private_key":"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"}`}},
		{"missing private key", map[string]any{"project_id": "acme-prod-001", "service_account_key_json": `{"type":"service_account","client_email":"x@y","private_key":""}`}},
		{"customer without admin", map[string]any{"project_id": "acme-prod-001", "workspace_customer_id": "my_customer", "service_account_key_json": fakeSAKey}},
		{"admin without customer", map[string]any{"project_id": "acme-prod-001", "workspace_admin_email": "ops@acme.com", "service_account_key_json": fakeSAKey}},
		{"bad customer id", map[string]any{"project_id": "acme-prod-001", "workspace_customer_id": "garbage", "workspace_admin_email": "ops@acme.com", "service_account_key_json": fakeSAKey}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.body)
			if _, _, err := (Connector{}).Validate(body); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}
