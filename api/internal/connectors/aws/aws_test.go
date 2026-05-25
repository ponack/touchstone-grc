package aws

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidate_RoleHappyPath(t *testing.T) {
	in := `{
		"account_id": "123456789012",
		"regions":    ["us-east-1", "eu-west-1"],
		"auth_method": "role",
		"role_arn":   "arn:aws:iam::123456789012:role/TouchstoneReadOnly",
		"external_id": "tx-abc-123"
	}`
	cfg, sec, err := New().Validate(json.RawMessage(in))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sec != nil {
		t.Fatal("role auth must not return a secret blob")
	}
	var p PublicConfig
	if err := json.Unmarshal(cfg, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.AuthMethod != "role" || p.RoleARN == "" || p.ExternalID == "" {
		t.Fatalf("config not preserved: %+v", p)
	}
}

func TestValidate_KeyHappyPath(t *testing.T) {
	in := `{
		"account_id": "123456789012",
		"regions":    ["us-east-1"],
		"auth_method": "KEY",
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	}`
	cfg, sec, err := New().Validate(json.RawMessage(in))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sec == nil {
		t.Fatal("key auth must return a secret blob")
	}
	var p PublicConfig
	if err := json.Unmarshal(cfg, &p); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	if p.AuthMethod != "key" {
		t.Fatalf("auth_method not lower-cased: %q", p.AuthMethod)
	}
	if strings.Contains(string(cfg), "AKIA") {
		t.Fatal("access key leaked into public config")
	}
	var s Secret
	if err := json.Unmarshal(sec, &s); err != nil {
		t.Fatalf("unmarshal secret: %v", err)
	}
	if s.AccessKeyID == "" || s.SecretAccessKey == "" {
		t.Fatalf("secret not preserved: %+v", s)
	}
}

func TestValidate_RegionsDeduped(t *testing.T) {
	in := `{
		"account_id": "123456789012",
		"regions":    ["us-east-1", "us-east-1", "eu-west-1"],
		"auth_method": "role",
		"role_arn":   "arn:aws:iam::123456789012:role/x"
	}`
	cfg, _, err := New().Validate(json.RawMessage(in))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	var p PublicConfig
	_ = json.Unmarshal(cfg, &p)
	if len(p.Regions) != 2 {
		t.Fatalf("regions not deduped: %v", p.Regions)
	}
}

func TestValidate_Rejects(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"bad account id", `{"account_id":"abc","regions":["us-east-1"],"auth_method":"role","role_arn":"arn:aws:iam::123456789012:role/x"}`},
		{"no regions", `{"account_id":"123456789012","regions":[],"auth_method":"role","role_arn":"arn:aws:iam::123456789012:role/x"}`},
		{"bad region", `{"account_id":"123456789012","regions":["US-EAST-1"],"auth_method":"role","role_arn":"arn:aws:iam::123456789012:role/x"}`},
		{"unknown auth_method", `{"account_id":"123456789012","regions":["us-east-1"],"auth_method":"saml"}`},
		{"role missing arn", `{"account_id":"123456789012","regions":["us-east-1"],"auth_method":"role"}`},
		{"key missing secret", `{"account_id":"123456789012","regions":["us-east-1"],"auth_method":"key","access_key_id":"AKIAIOSFODNN7EXAMPLE"}`},
		{"malformed json", `{"account_id":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := (Connector{}).Validate(json.RawMessage(tc.body)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}
