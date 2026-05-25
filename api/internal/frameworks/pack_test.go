package frameworks

import (
	"strings"
	"testing"
)

func TestParsePack_HappyPath(t *testing.T) {
	raw := []byte(`
code: soc2_2017
name: SOC 2 (2017)
version: "2017"
controls:
  - code: CC6.1
    title: Logical access controls
    description: blah
    severity: high
    policy_path: soc2_2017/cc6_1.rego
  - code: CC7.1
    title: Vulnerability detection
    policy_path: soc2_2017/cc7_1.rego
`)
	p, err := ParsePack(raw)
	if err != nil {
		t.Fatalf("ParsePack: %v", err)
	}
	if p.Code != "soc2_2017" {
		t.Fatalf("code: %q", p.Code)
	}
	if len(p.Controls) != 2 {
		t.Fatalf("got %d controls", len(p.Controls))
	}
	if p.Controls[1].Severity != "medium" {
		t.Fatalf("default severity not applied: %q", p.Controls[1].Severity)
	}
}

func TestParsePack_Rejects(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"no code", `name: x
controls:
  - code: a
    title: t
    policy_path: p`, "code is required"},
		{"no name", `code: x
controls:
  - code: a
    title: t
    policy_path: p`, "name is required"},
		{"no controls", `code: x
name: y`, "at least one control"},
		{"duplicate control", `code: x
name: y
controls:
  - {code: a, title: t, policy_path: p}
  - {code: a, title: t, policy_path: p}`, "duplicate control code"},
		{"missing title", `code: x
name: y
controls:
  - {code: a, policy_path: p}`, "title is required"},
		{"missing policy_path", `code: x
name: y
controls:
  - {code: a, title: t}`, "policy_path is required"},
		{"bad severity", `code: x
name: y
controls:
  - {code: a, title: t, policy_path: p, severity: catastrophic}`, "invalid severity"},
		{"malformed yaml", `code: [`, "yaml:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePack([]byte(tc.raw))
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
