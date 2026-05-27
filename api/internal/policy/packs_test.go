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

// ── CC6.6 — S3 public access controls ───────────────────────────────────────

func lockedBucket() map[string]any {
	return map[string]any{
		"type": "aws.s3.bucket",
		"id":   "arn:aws:s3:::locked",
		"attrs": map[string]any{
			"public_access_block": map[string]any{
				"block_public_acls":       true,
				"ignore_public_acls":      true,
				"block_public_policy":     true,
				"restrict_public_buckets": true,
			},
			"policy_status": map[string]any{"is_public": false},
			"encryption":    map[string]any{"enabled": true, "algorithm": "AES256"},
		},
	}
}

func TestCC6_6_PassesWhenAllBucketsLocked(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{"resources": []any{lockedBucket()}}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC6_6_FailsOnPolicyPublicBucket(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{
		"resources": []any{
			lockedBucket(),
			map[string]any{
				"type": "aws.s3.bucket",
				"id":   "arn:aws:s3:::leaky",
				"attrs": map[string]any{
					"public_access_block": map[string]any{
						"block_public_acls":       true,
						"ignore_public_acls":      true,
						"block_public_policy":     true,
						"restrict_public_buckets": true,
					},
					"policy_status": map[string]any{"is_public": true},
					"encryption":    map[string]any{"enabled": true, "algorithm": "AES256"},
				},
			},
		},
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
	if len(d.Failures) != 1 {
		t.Fatalf("got %d failures, want 1; %v", len(d.Failures), d.Failures)
	}
}

func TestCC6_6_FailsWhenBPAFlagDisabled(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bad := lockedBucket()
	bad["id"] = "arn:aws:s3:::partial"
	bpa := bad["attrs"].(map[string]any)["public_access_block"].(map[string]any)
	bpa["restrict_public_buckets"] = false
	input := map[string]any{"resources": []any{bad}}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_6_NotApplicableWhenNoBuckets(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego", map[string]any{"resources": []any{}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// ── CC6.7 — S3 encryption ───────────────────────────────────────────────────

func TestCC6_7_PassesWhenAllBucketsEncrypted(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{"resources": []any{lockedBucket()}}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_7.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC6_7_FailsWhenEncryptionDisabled(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bad := lockedBucket()
	bad["id"] = "arn:aws:s3:::unencrypted"
	bad["attrs"].(map[string]any)["encryption"] = map[string]any{"enabled": false}
	input := map[string]any{"resources": []any{bad}}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_7.rego", input)
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

// ── CC6.6 — EC2 Security Groups ─────────────────────────────────────────────

func sgResource(id string, rules []any) map[string]any {
	return map[string]any{
		"type": "aws.ec2.security_group",
		"id":   id,
		"attrs": map[string]any{
			"group_id":      id[len(id)-11:], // last "sg-xxxxxx"
			"region":        "us-east-1",
			"ingress_rules": rules,
		},
	}
}

func sgRule(proto string, from, to int, v4, v6 []any) map[string]any {
	return map[string]any{
		"protocol":   proto,
		"from_port":  from,
		"to_port":    to,
		"ipv4_cidrs": v4,
		"ipv6_cidrs": v6,
	}
}

func TestCC6_6_FailsOnWorldOpenSSH(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	sg := sgResource("arn:aws:ec2:us-east-1::security-group/sg-bad01234", []any{
		sgRule("tcp", 22, 22, []any{"0.0.0.0/0"}, []any{}),
	})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego", map[string]any{"resources": []any{sg}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail; message=%q", d.Status, d.Message)
	}
}

func TestCC6_6_FailsOnAllProtocolsWorldOpen(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	sg := sgResource("arn:aws:ec2:us-east-1::security-group/sg-allprot01", []any{
		sgRule("-1", 0, 65535, []any{"0.0.0.0/0"}, []any{}),
	})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego", map[string]any{"resources": []any{sg}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_6_PassesOnRestrictedIngress(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	sg := sgResource("arn:aws:ec2:us-east-1::security-group/sg-private01", []any{
		// Webserver: world-open 443 is intentionally OK.
		sgRule("tcp", 443, 443, []any{"0.0.0.0/0"}, []any{}),
		// SSH only from corporate CIDR.
		sgRule("tcp", 22, 22, []any{"10.0.0.0/8"}, []any{}),
	})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego", map[string]any{"resources": []any{sg}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC6_6_FailsWhenRangeCoversSensitivePort(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	// 1000-4000 world-open covers MySQL (3306) and MS SQL (1433).
	sg := sgResource("arn:aws:ec2:us-east-1::security-group/sg-range0001", []any{
		sgRule("tcp", 1000, 4000, []any{"0.0.0.0/0"}, []any{}),
	})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego", map[string]any{"resources": []any{sg}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

// ── CC7.2 — CloudTrail system monitoring ────────────────────────────────────

func compliantTrail() map[string]any {
	return map[string]any{
		"type": "aws.cloudtrail.trail",
		"id":   "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-audit",
		"attrs": map[string]any{
			"name":                          "org-audit",
			"home_region":                   "us-east-1",
			"is_multi_region":               true,
			"include_global_service_events": true,
			"log_file_validation_enabled":   true,
			"is_logging":                    true,
		},
	}
}

// Add one IAM user so aws_scanned fires (CC7.2 only applies when we
// actually touched AWS).
func awsMarker() map[string]any {
	return map[string]any{
		"type": "aws.iam.user",
		"id":   "arn:aws:iam::123456789012:user/x",
		"attrs": map[string]any{
			"has_console": false,
			"mfa_devices": []any{},
			"access_keys": []any{},
		},
	}
}

func TestCC7_2_PassesWhenCompliantTrailExists(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{"resources": []any{compliantTrail(), awsMarker()}}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC7_2_FailsWhenNoTrails(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{"resources": []any{awsMarker()}}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail; message=%q", d.Status, d.Message)
	}
	if len(d.Failures) != 1 {
		t.Fatalf("got %d failures, want 1", len(d.Failures))
	}
}

func TestCC7_2_FailsWhenTrailMissingMultiRegion(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bad := compliantTrail()
	bad["attrs"].(map[string]any)["is_multi_region"] = false
	input := map[string]any{"resources": []any{bad, awsMarker()}}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_2_FailsWhenTrailNotLogging(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bad := compliantTrail()
	bad["attrs"].(map[string]any)["is_logging"] = false
	input := map[string]any{"resources": []any{bad, awsMarker()}}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

// One compliant trail + several non-compliant trails should still pass —
// the control is about whether monitoring exists, not whether every
// trail is perfect.
func TestCC7_2_PassesWithOneCompliantAmongMany(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bad := compliantTrail()
	bad["id"] = "arn:aws:cloudtrail:us-east-1:123456789012:trail/scratch"
	bad["attrs"].(map[string]any)["is_multi_region"] = false
	bad["attrs"].(map[string]any)["log_file_validation_enabled"] = false
	input := map[string]any{"resources": []any{compliantTrail(), bad, awsMarker()}}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC7_2_NotApplicableWhenNoAWSResources(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego", map[string]any{"resources": []any{}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// ── CC6.8 + CC7.3 — GuardDuty ───────────────────────────────────────────────
// Both controls share the same evaluation surface for v0 (GuardDuty
// detectors enabled), so tests live together.

func enabledDetector(region string) map[string]any {
	return map[string]any{
		"type": "aws.guardduty.detector",
		"id":   "arn:aws:guardduty:" + region + ":detector/abcd",
		"attrs": map[string]any{
			"detector_id": "abcd",
			"region":      region,
			"status":      "ENABLED",
		},
	}
}

func disabledDetector(region string) map[string]any {
	d := enabledDetector(region)
	d["attrs"].(map[string]any)["status"] = "DISABLED"
	return d
}

func runGuardDutyTest(t *testing.T, control string, resources []any, wantStatus string) {
	t.Helper()
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), control, map[string]any{"resources": resources})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != wantStatus {
		t.Fatalf("control=%s status=%q want=%q; message=%q", control, d.Status, wantStatus, d.Message)
	}
}

func TestCC6_8_PassesWhenAllDetectorsEnabled(t *testing.T) {
	runGuardDutyTest(t, "soc2_2017/cc6_8.rego",
		[]any{enabledDetector("us-east-1"), enabledDetector("eu-west-1"), awsMarker()},
		"pass")
}

func TestCC6_8_FailsWhenNoDetectors(t *testing.T) {
	runGuardDutyTest(t, "soc2_2017/cc6_8.rego",
		[]any{awsMarker()},
		"fail")
}

func TestCC6_8_FailsWhenAnyDetectorDisabled(t *testing.T) {
	runGuardDutyTest(t, "soc2_2017/cc6_8.rego",
		[]any{enabledDetector("us-east-1"), disabledDetector("eu-west-1"), awsMarker()},
		"fail")
}

func TestCC6_8_NotApplicableOnNonAWS(t *testing.T) {
	runGuardDutyTest(t, "soc2_2017/cc6_8.rego", []any{}, "not_applicable")
}

func TestCC7_3_PassesWhenAllDetectorsEnabled(t *testing.T) {
	runGuardDutyTest(t, "soc2_2017/cc7_3.rego",
		[]any{enabledDetector("us-east-1"), awsMarker()},
		"pass")
}

func TestCC7_3_FailsWhenNoDetectors(t *testing.T) {
	runGuardDutyTest(t, "soc2_2017/cc7_3.rego",
		[]any{awsMarker()},
		"fail")
}

func TestCC7_3_FailsWhenAnyDetectorDisabled(t *testing.T) {
	runGuardDutyTest(t, "soc2_2017/cc7_3.rego",
		[]any{enabledDetector("us-east-1"), disabledDetector("eu-west-1"), awsMarker()},
		"fail")
}
