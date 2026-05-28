package github

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidate_HappyPath(t *testing.T) {
	in := `{"org": "forged-in-feathers", "access_token": "ghp_abcdefghijklmnop1234567890"}`
	cfg, sec, err := New().Validate(json.RawMessage(in))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sec == nil {
		t.Fatal("expected secret blob")
	}
	if strings.Contains(string(cfg), "ghp_") || strings.Contains(string(cfg), "access_token") {
		t.Fatal("access_token leaked into public config")
	}
	var p PublicConfig
	if err := json.Unmarshal(cfg, &p); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	if p.Org != "forged-in-feathers" {
		t.Fatalf("org not preserved: %q", p.Org)
	}
}

func TestValidate_Rejects(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty org", `{"org": "", "access_token": "ghp_abcdefghijklmnop1234567890"}`},
		{"org with leading dash", `{"org": "-bad", "access_token": "ghp_abcdefghijklmnop1234567890"}`},
		{"org with special chars", `{"org": "bad org!", "access_token": "ghp_abcdefghijklmnop1234567890"}`},
		{"org too long", `{"org": "` + strings.Repeat("a", 40) + `", "access_token": "ghp_abcdefghijklmnop1234567890"}`},
		{"short token", `{"org": "foo", "access_token": "ghp_short"}`},
		{"malformed json", `{"org":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := (Connector{}).Validate(json.RawMessage(tc.body)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestValidate_AcceptsSingleCharOrg(t *testing.T) {
	in := `{"org": "a", "access_token": "ghp_abcdefghijklmnop1234567890"}`
	if _, _, err := New().Validate(json.RawMessage(in)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestNextLink(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{`<https://api.github.com/foo?page=2>; rel="next"`, "https://api.github.com/foo?page=2"},
		{`<https://api.github.com/foo?page=2>; rel="next", <https://api.github.com/foo?page=10>; rel="last"`, "https://api.github.com/foo?page=2"},
		{`<https://api.github.com/foo?page=1>; rel="prev", <https://api.github.com/foo?page=10>; rel="last"`, ""},
	}
	for _, tc := range cases {
		if got := nextLink(tc.in); got != tc.want {
			t.Errorf("nextLink(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
