package policy_test

import (
	"context"
	"testing"

	"github.com/ponack/touchstone/internal/frameworks/packs"
	"github.com/ponack/touchstone/internal/policy"
)

// TestRealPacksCompile loads every embedded rego policy through the
// engine. Any syntax error in a control pack rego file now fails CI,
// catching broken policies before they ship.
func TestRealPacksCompile(t *testing.T) {
	if _, err := policy.NewEngine(packs.FS); err != nil {
		t.Fatalf("NewEngine on real packs: %v", err)
	}
}

// TestCC6_1_PassesWhenAllUsersHaveMFA exercises the real SOC 2 CC6.1
// policy against a hand-crafted IAM input. Catches structural drift
// between the rego and the AWS scanner's resource shape.
func TestCC6_1_PassesWhenAllUsersHaveMFA(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{
		"resources": []any{
			map[string]any{
				"type": "aws.iam.user",
				"id":   "arn:aws:iam::123456789012:user/alice",
				"attrs": map[string]any{
					"user_name":   "alice",
					"has_console": true,
					"mfa_devices": []any{
						map[string]any{"serial_number": "arn", "enable_date": "2024-01-01T00:00:00Z"},
					},
					"access_keys": []any{},
				},
			},
		},
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_1.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

// TestCC6_1_FailsWhenConsoleUserHasNoMFA exercises the violation
// branch of CC6.1.
func TestCC6_1_FailsWhenConsoleUserHasNoMFA(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{
		"resources": []any{
			map[string]any{
				"type": "aws.iam.user",
				"id":   "arn:aws:iam::123456789012:user/bob",
				"attrs": map[string]any{
					"user_name":   "bob",
					"has_console": true,
					"mfa_devices": []any{},
					"access_keys": []any{},
				},
			},
		},
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_1.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
	if len(d.Failures) != 1 {
		t.Fatalf("got %d failures, want 1", len(d.Failures))
	}
}

// TestCC6_1_NotApplicableWhenNoIAMUsers covers the empty-scan case.
func TestCC6_1_NotApplicableWhenNoIAMUsers(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_1.rego", map[string]any{"resources": []any{}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// TestCC6_3_PassesWhenAllKeysFresh confirms recent access keys do
// not trigger the stale-key rule.
func TestCC6_3_PassesWhenAllKeysFresh(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{
		"resources": []any{
			map[string]any{
				"type": "aws.iam.user",
				"id":   "arn:aws:iam::123456789012:user/alice",
				"attrs": map[string]any{
					"has_console": true,
					"mfa_devices": []any{map[string]any{"serial_number": "arn"}},
					"access_keys": []any{
						map[string]any{
							"access_key_id": "AKIAEXAMPLE",
							"status":        "Active",
							"create_date":   "2026-05-01T00:00:00Z",
						},
					},
				},
			},
		},
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_3.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

// TestCC6_3_FailsWhenKeyOlderThanYear confirms the stale-key rule fires.
func TestCC6_3_FailsWhenKeyOlderThanYear(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{
		"resources": []any{
			map[string]any{
				"type": "aws.iam.user",
				"id":   "arn:aws:iam::123456789012:user/legacy",
				"attrs": map[string]any{
					"has_console": false,
					"mfa_devices": []any{},
					"access_keys": []any{
						map[string]any{
							"access_key_id": "AKIAOLD",
							"status":        "Active",
							"create_date":   "2020-01-01T00:00:00Z",
						},
					},
				},
			},
		},
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_3.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail; message=%q", d.Status, d.Message)
	}
}
