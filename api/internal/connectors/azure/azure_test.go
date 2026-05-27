package azure

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidate_HappyPath(t *testing.T) {
	in := `{
		"tenant_id":      "12345678-1234-1234-1234-1234567890ab",
		"client_id":      "abcdef01-2345-6789-abcd-ef0123456789",
		"client_secret": "Sa~M9o-iEi.SQXh89gjmAa4Jbz9xkOf4tw"
	}`
	cfg, sec, err := New().Validate(json.RawMessage(in))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sec == nil {
		t.Fatal("expected secret blob")
	}
	if strings.Contains(string(cfg), "client_secret") || strings.Contains(string(cfg), "Sa~M9o") {
		t.Fatal("client_secret leaked into public config")
	}
	var p PublicConfig
	if err := json.Unmarshal(cfg, &p); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	if p.TenantID == "" {
		t.Fatal("tenant_id not preserved")
	}
}

func TestValidate_AcceptsOptionalSubscriptionID(t *testing.T) {
	in := `{
		"tenant_id":        "12345678-1234-1234-1234-1234567890ab",
		"subscription_id": "00000000-0000-0000-0000-000000000000",
		"client_id":        "abcdef01-2345-6789-abcd-ef0123456789",
		"client_secret":   "Sa~M9o-iEi.SQXh89gjmAa4Jbz9xkOf4tw"
	}`
	cfg, _, err := New().Validate(json.RawMessage(in))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	var p PublicConfig
	_ = json.Unmarshal(cfg, &p)
	if p.SubscriptionID == "" {
		t.Fatal("subscription_id should be preserved when provided")
	}
}

func TestValidate_Rejects(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"non-guid tenant", `{"tenant_id":"not-a-guid","client_id":"abcdef01-2345-6789-abcd-ef0123456789","client_secret":"secrets!!"}`},
		{"non-guid subscription", `{"tenant_id":"12345678-1234-1234-1234-1234567890ab","subscription_id":"bad","client_id":"abcdef01-2345-6789-abcd-ef0123456789","client_secret":"secrets!!"}`},
		{"non-guid client", `{"tenant_id":"12345678-1234-1234-1234-1234567890ab","client_id":"bad","client_secret":"secrets!!"}`},
		{"short client secret", `{"tenant_id":"12345678-1234-1234-1234-1234567890ab","client_id":"abcdef01-2345-6789-abcd-ef0123456789","client_secret":"x"}`},
		{"malformed json", `{"tenant_id":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := (Connector{}).Validate(json.RawMessage(tc.body)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}
