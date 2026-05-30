package policy_test

import (
	"context"
	"testing"
	"time"

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

// ── CC6.1 — Azure AD users ──────────────────────────────────────────────────

func azureUser(upn string, mfaCapable, mfaRegistered bool, userType string) map[string]any {
	return map[string]any{
		"type": "azure.ad.user",
		"id":   "azure-ad://tenant/users/" + upn,
		"attrs": map[string]any{
			"user_principal_name": upn,
			"display_name":        upn,
			"user_type":           userType,
			"is_mfa_capable":      mfaCapable,
			"is_mfa_registered":   mfaRegistered,
		},
	}
}

func TestCC6_1_PassesWhenAzureUsersHaveMFA(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{
		"resources": []any{azureUser("alice@example.com", true, true, "Member")},
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_1.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC6_1_FailsWhenAzureMemberLacksMFA(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{
		"resources": []any{azureUser("bob@example.com", true, false, "Member")},
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

// Guests are intentionally excluded — they're invited external users
// whose MFA is the responsibility of their home tenant.
func TestCC6_1_DoesNotFailOnAzureGuest(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := map[string]any{
		"resources": []any{azureUser("partner@vendor.com", true, false, "Guest")},
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_1.rego", input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass (guests are out of scope)", d.Status)
	}
}

// A scan with both AWS and Azure identities + one bad user in each
// surfaces two violations.
func TestCC6_1_MixedCloudViolations(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	awsUser := map[string]any{
		"type": "aws.iam.user",
		"id":   "arn:aws:iam::123456789012:user/no-mfa",
		"attrs": map[string]any{
			"has_console": true,
			"mfa_devices": []any{},
		},
	}
	az := azureUser("naked@example.com", true, false, "Member")
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_1.rego",
		map[string]any{"resources": []any{awsUser, az}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
	if len(d.Failures) != 2 {
		t.Fatalf("got %d failures, want 2", len(d.Failures))
	}
}

// ── CC6.1 — GCP Workspace users ─────────────────────────────────────────────

func gcpUser(email string, enrolled2sv, suspended bool) map[string]any {
	return map[string]any{
		"type": "gcp.iam.user",
		"id":   "gcp-workspace://my_customer/users/" + email,
		"attrs": map[string]any{
			"primary_email":   email,
			"is_enrolled_2sv": enrolled2sv,
			"is_enforced_2sv": enrolled2sv,
			"suspended":       suspended,
			"is_admin":        false,
		},
	}
}

func TestCC6_1_PassesWhenGCPUsersEnrolledIn2SV(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_1.rego",
		map[string]any{"resources": []any{gcpUser("alice@example.com", true, false)}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC6_1_FailsWhenGCPActiveUserMissing2SV(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_1.rego",
		map[string]any{"resources": []any{gcpUser("bob@example.com", false, false)}})
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

// Suspended accounts can't authenticate, so they're excluded from the
// MFA rule even when 2SV is not enrolled.
func TestCC6_1_DoesNotFailOnSuspendedGCPUser(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_1.rego",
		map[string]any{"resources": []any{gcpUser("former@example.com", false, true)}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass (suspended users out of scope)", d.Status)
	}
}

// Tri-cloud violation surface: AWS, Azure and GCP each contribute
// one finding.
func TestCC6_1_TriCloudViolations(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	awsUser := map[string]any{
		"type": "aws.iam.user",
		"id":   "arn:aws:iam::123456789012:user/no-mfa",
		"attrs": map[string]any{
			"has_console": true,
			"mfa_devices": []any{},
		},
	}
	az := azureUser("naked@example.com", true, false, "Member")
	g := gcpUser("naked@example.com", false, false)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_1.rego",
		map[string]any{"resources": []any{awsUser, az, g}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
	if len(d.Failures) != 3 {
		t.Fatalf("got %d failures, want 3", len(d.Failures))
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

// ── CC6.3 — Azure AD application credential rotation ────────────────────────

func azureApp(name string, passCreds, keyCreds []any) map[string]any {
	return map[string]any{
		"type": "azure.ad.application",
		"id":   "azure-ad://tenant/applications/" + name,
		"attrs": map[string]any{
			"app_id":               name + "-id",
			"display_name":         name,
			"password_credentials": passCreds,
			"key_credentials":      keyCreds,
		},
	}
}

func azureCred(displayName string, startISO, endISO string) map[string]any {
	return map[string]any{
		"key_id":       displayName,
		"display_name": displayName,
		"start_date":   startISO,
		"end_date":     endISO,
	}
}

func TestCC6_3_PassesOnRecentAzureSecret(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	// Secret issued recently, still valid → not stale.
	recent := azureCred("rotated-secret", "2026-05-01T00:00:00Z", "2027-05-01T00:00:00Z")
	app := azureApp("prod-svc", []any{recent}, []any{})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_3.rego",
		map[string]any{"resources": []any{app}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC6_3_FailsOnStaleAzureSecret(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	// Secret issued in 2020, expires 2030 — currently valid AND
	// older than 365 days.
	stale := azureCred("legacy-secret", "2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
	app := azureApp("legacy-svc", []any{stale}, []any{})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_3.rego",
		map[string]any{"resources": []any{app}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_3_FailsOnStaleAzureCertificate(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	stale := azureCred("legacy-cert", "2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
	app := azureApp("legacy-svc", []any{}, []any{stale})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_3.rego",
		map[string]any{"resources": []any{app}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

// Expired credentials are ignored — they no longer grant access so
// they're not a rotation finding.
func TestCC6_3_IgnoresExpiredAzureCredential(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	expired := azureCred("old-and-dead", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z")
	app := azureApp("legacy-svc", []any{expired}, []any{})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_3.rego",
		map[string]any{"resources": []any{app}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass (expired credentials are not findings)", d.Status)
	}
}

// ── CC6.3 — GCP service account key rotation ────────────────────────────────

func gcpSAKey(id, keyType, validAfter string) map[string]any {
	return map[string]any{
		"id":               id,
		"key_type":         keyType,
		"valid_after_time": validAfter,
	}
}

func gcpServiceAccount(email string, keys []any) map[string]any {
	return map[string]any{
		"type": "gcp.iam.service_account",
		"id":   "gcp-iam://acme-prod-001/serviceAccounts/" + email,
		"attrs": map[string]any{
			"email":        email,
			"unique_id":    "111222333444555666777",
			"display_name": "Test SA",
			"disabled":     false,
			"keys":         keys,
		},
	}
}

func TestCC6_3_PassesWhenGCPKeyFresh(t *testing.T) {
	// Key minted yesterday — well within rotation window.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	fresh := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	sa := gcpServiceAccount("scanner@acme.iam.gserviceaccount.com",
		[]any{gcpSAKey("abc123", "USER_MANAGED", fresh)})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_3.rego",
		map[string]any{"resources": []any{sa}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC6_3_FailsWhenGCPKeyOlderThanYear(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	stale := time.Now().Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	sa := gcpServiceAccount("legacy@acme.iam.gserviceaccount.com",
		[]any{gcpSAKey("def456", "USER_MANAGED", stale)})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_3.rego",
		map[string]any{"resources": []any{sa}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

// System-managed keys are Google-rotated and out of scope for CC6.3.
// The scanner should already filter them, but the rego must also
// ignore any that slip through.
func TestCC6_3_IgnoresSystemManagedGCPKey(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	stale := time.Now().Add(-1000 * 24 * time.Hour).UTC().Format(time.RFC3339)
	sa := gcpServiceAccount("system-mgmt@acme.iam.gserviceaccount.com",
		[]any{gcpSAKey("xyz", "SYSTEM_MANAGED", stale)})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_3.rego",
		map[string]any{"resources": []any{sa}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass (system-managed keys ignored)", d.Status)
	}
}

// ── CC6.6 — S3 public access controls ───────────────────────────────────────

func lockedBucket() map[string]any {
	return map[string]any{
		"type": "aws.s3.bucket",
		"id":   "arn:aws:s3:::locked",
		"attrs": map[string]any{
			"name": "locked",
			"public_access_block": map[string]any{
				"block_public_acls":       true,
				"ignore_public_acls":      true,
				"block_public_policy":     true,
				"restrict_public_buckets": true,
			},
			"policy_status":         map[string]any{"is_public": false},
			"encryption":            map[string]any{"enabled": true, "algorithm": "AES256"},
			"versioning_enabled":    true,
			"versioning_mfa_delete": true,
			"enforces_https_only":   true,
		},
	}
}

// awsS3Bucket builds a bucket resource with explicit knobs for the
// four CIS Section 2.1 rules. Pass true for "compliant" defaults.
func awsS3Bucket(name string, encEnabled, httpsOnly, mfaDelete bool, bpa map[string]any) map[string]any {
	if bpa == nil {
		bpa = map[string]any{
			"block_public_acls":       true,
			"ignore_public_acls":      true,
			"block_public_policy":     true,
			"restrict_public_buckets": true,
		}
	}
	return map[string]any{
		"type": "aws.s3.bucket",
		"id":   "arn:aws:s3:::" + name,
		"attrs": map[string]any{
			"name":                  name,
			"public_access_block":   bpa,
			"policy_status":         map[string]any{"is_public": false},
			"encryption":            map[string]any{"enabled": encEnabled, "algorithm": "AES256"},
			"versioning_enabled":    true,
			"versioning_mfa_delete": mfaDelete,
			"enforces_https_only":   httpsOnly,
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

// ── Azure Storage — CC6.6 + CC6.7 ───────────────────────────────────────────

func azureStorage(name string, opts map[string]any) map[string]any {
	attrs := map[string]any{
		"name":                      name,
		"subscription_id":           "00000000-0000-0000-0000-000000000000",
		"location":                  "eastus",
		"kind":                      "StorageV2",
		"sku":                       "Standard_LRS",
		"allow_blob_public_access":  false,
		"enable_https_traffic_only": true,
		"minimum_tls_version":       "TLS1_2",
		"public_network_access":     "Enabled",
		"encryption_key_source":     "Microsoft.Storage",
	}
	for k, v := range opts {
		attrs[k] = v
	}
	return map[string]any{
		"type":  "azure.storage.account",
		"id":    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/" + name,
		"attrs": attrs,
	}
}

func TestCC6_6_FailsOnAzurePublicBlobAccess(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	sa := azureStorage("leaky", map[string]any{"allow_blob_public_access": true})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{sa}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_6_PassesOnLockedDownAzureStorage(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	sa := azureStorage("locked", nil)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{sa}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC6_7_FailsOnAzureHTTPAllowed(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	sa := azureStorage("plaintext", map[string]any{"enable_https_traffic_only": false})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_7.rego",
		map[string]any{"resources": []any{sa}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_7_FailsOnAzureOldTLS(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	sa := azureStorage("old-tls", map[string]any{"minimum_tls_version": "TLS1_0"})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_7.rego",
		map[string]any{"resources": []any{sa}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_7_PassesOnEncryptedAzureStorage(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	sa := azureStorage("good", nil)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_7.rego",
		map[string]any{"resources": []any{sa}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

// ── CC6.6 / CC6.7 — GCP Cloud Storage ───────────────────────────────────────

func gcpBucket(name, publicAccessPrevention string, publicBindings []any) map[string]any {
	return map[string]any{
		"type": "gcp.storage.bucket",
		"id":   "gcp-storage://acme-prod-001/buckets/" + name,
		"attrs": map[string]any{
			"name":                        name,
			"project":                     "acme-prod-001",
			"location":                    "US",
			"public_access_prevention":    publicAccessPrevention,
			"uniform_bucket_level_access": true,
			"default_kms_key_name":        "",
			"iam_public_bindings":         publicBindings,
		},
	}
}

func TestCC6_6_PassesOnLockedDownGCSBucket(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	b := gcpBucket("private-data", "enforced", []any{})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{b}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC6_6_FailsOnGCSBucketWithGateOpen(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	b := gcpBucket("loose", "inherited", []any{})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{b}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_6_FailsOnGCSBucketWithPublicIAMBinding(t *testing.T) {
	// publicAccessPrevention is "enforced" but a stale public IAM
	// binding survives. Both checks fire — the public binding is
	// the actual exposure.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	b := gcpBucket("legacy-public", "enforced", []any{"roles/storage.objectViewer:allUsers"})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{b}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

// GCS platform enforces TLS-only access + default at-rest encryption,
// so the bucket flips CC6.7 to applicable but never to failing on its
// own.
func TestCC6_7_PassesOnGCSBucket(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	b := gcpBucket("private-data", "enforced", []any{})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_7.rego",
		map[string]any{"resources": []any{b}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

// ── CC6.6 — GCP VPC firewall ────────────────────────────────────────────────

func gcpFirewallRule(protocol string, from, to int) map[string]any {
	return map[string]any{
		"protocol":  protocol,
		"from_port": from,
		"to_port":   to,
	}
}

func gcpFirewall(name string, sources []any, ingress []any) map[string]any {
	return map[string]any{
		"type": "gcp.compute.firewall",
		"id":   "gcp-compute://acme-prod-001/firewalls/" + name,
		"attrs": map[string]any{
			"name":          name,
			"network":       "global/networks/default",
			"priority":      1000,
			"direction":     "INGRESS",
			"source_ranges": sources,
			"ingress_rules": ingress,
		},
	}
}

func TestCC6_6_FailsOnGCPFirewallWorldOpenSSH(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	fw := gcpFirewall("allow-ssh-world",
		[]any{"0.0.0.0/0"},
		[]any{gcpFirewallRule("tcp", 22, 22)},
	)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{fw}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_6_FailsOnGCPFirewallAllProtocolsWorldOpen(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	fw := gcpFirewall("kitchen-sink",
		[]any{"0.0.0.0/0"},
		[]any{gcpFirewallRule("all", 0, 65535)},
	)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{fw}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_6_FailsOnGCPFirewallRangeHitsSensitivePort(t *testing.T) {
	// A range 20-30 covers SSH (22) — must fail even though the
	// rule doesn't name port 22 directly.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	fw := gcpFirewall("wide-range",
		[]any{"0.0.0.0/0"},
		[]any{gcpFirewallRule("tcp", 20, 30)},
	)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{fw}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_6_PassesOnGCPFirewallScopedToCorpRange(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	fw := gcpFirewall("allow-ssh-corp",
		[]any{"10.0.0.0/8"},
		[]any{gcpFirewallRule("tcp", 22, 22)},
	)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{fw}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

// Public web traffic is legitimate — 443 from 0.0.0.0/0 must pass.
func TestCC6_6_PassesOnGCPFirewallWorldOpenHTTPS(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	fw := gcpFirewall("allow-https",
		[]any{"0.0.0.0/0"},
		[]any{gcpFirewallRule("tcp", 443, 443)},
	)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{fw}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
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

// ── Azure NSG — CC6.6 ───────────────────────────────────────────────────────

func azureNSG(name string, inbound []any) map[string]any {
	return map[string]any{
		"type": "azure.network.nsg",
		"id":   "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/" + name,
		"attrs": map[string]any{
			"name":            name,
			"subscription_id": "sub",
			"location":        "eastus",
			"inbound_rules":   inbound,
		},
	}
}

func azureNSGRule(name, protocol string, from, to int, sources []any) map[string]any {
	return map[string]any{
		"name":            name,
		"priority":        100,
		"protocol":        protocol,
		"from_port":       from,
		"to_port":         to,
		"source_prefixes": sources,
	}
}

func TestCC6_6_FailsOnAzureNSGSSHWorldOpen(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	nsg := azureNSG("prod", []any{
		azureNSGRule("allow-ssh", "Tcp", 22, 22, []any{"*"}),
	})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{nsg}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_6_FailsOnAzureNSGInternetTag(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	nsg := azureNSG("prod", []any{
		azureNSGRule("allow-rdp", "Tcp", 3389, 3389, []any{"Internet"}),
	})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{nsg}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_6_FailsOnAzureNSGAllProtocols(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	nsg := azureNSG("prod", []any{
		azureNSGRule("nuke", "*", 0, 65535, []any{"*"}),
	})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{nsg}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_6_PassesOnAzureNSGRestricted(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	// Webserver SG: world-open 443 (OK), SSH from corp CIDR only (OK).
	nsg := azureNSG("prod", []any{
		azureNSGRule("allow-https", "Tcp", 443, 443, []any{"*"}),
		azureNSGRule("allow-ssh-corp", "Tcp", 22, 22, []any{"10.0.0.0/8"}),
	})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_6.rego",
		map[string]any{"resources": []any{nsg}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
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

// ── CC7.2 — Azure Activity Log diagnostic settings ──────────────────────────

func azureMonitorSetting(name string, opts map[string]any) map[string]any {
	cats := map[string]any{"Administrative": true, "Security": true}
	attrs := map[string]any{
		"name":               name,
		"subscription_id":    "sub",
		"has_workspace_sink": true,
		"has_storage_sink":   false,
		"has_eventhub_sink":  false,
		"categories":         cats,
	}
	for k, v := range opts {
		attrs[k] = v
	}
	return map[string]any{
		"type":  "azure.monitor.activity_log_setting",
		"id":    "/subscriptions/sub/providers/microsoft.insights/diagnosticSettings/" + name,
		"attrs": attrs,
	}
}

// awsMarker (defined later in the CC7.2 tests) provides an aws.* resource.
// For Azure we use an Azure AD user to satisfy azure_scanned.
func azureMarker() map[string]any {
	return azureUser("anyone@example.com", true, true, "Member")
}

func TestCC7_2_PassesWhenAzureSettingForwardsToWorkspace(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	s := azureMonitorSetting("to-loganalytics", nil)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego",
		map[string]any{"resources": []any{s, azureMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC7_2_FailsWhenAzureScannedButNoSettings(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego",
		map[string]any{"resources": []any{azureMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_2_FailsWhenAzureSettingHasNoSink(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	s := azureMonitorSetting("sinkless", map[string]any{
		"has_workspace_sink": false,
		"has_storage_sink":   false,
		"has_eventhub_sink":  false,
	})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego",
		map[string]any{"resources": []any{s, azureMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_2_FailsWhenAzureSettingMissingCategory(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cats := map[string]any{"Administrative": true, "Security": false}
	s := azureMonitorSetting("incomplete", map[string]any{"categories": cats})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego",
		map[string]any{"resources": []any{s, azureMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

// Mixed-cloud scan: AWS compliant, Azure not → fail (Azure side).
func TestCC7_2_MixedFailsOnAzureGap(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego",
		map[string]any{"resources": []any{compliantTrail(), awsMarker(), azureMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail (Azure scanned but no diagnostic settings)", d.Status)
	}
}

// ── CC7.2 — GCP Cloud Logging sinks ─────────────────────────────────────────

func gcpSink(name, destinationType string, capturesAdmin, durable bool) map[string]any {
	return map[string]any{
		"type": "gcp.logging.sink",
		"id":   "gcp-logging://acme-prod-001/sinks/" + name,
		"attrs": map[string]any{
			"name":                    name,
			"destination":             destinationType + ".googleapis.com/projects/acme/x",
			"destination_type":        destinationType,
			"filter":                  "",
			"captures_admin_activity": capturesAdmin,
			"is_durable_export":       durable,
		},
	}
}

// gcpMarker provides any gcp.* resource to satisfy gcp_scanned in
// rules that need an anchor to trigger applicability.
func gcpMarker() map[string]any {
	return gcpUser("anyone@example.com", true, false)
}

func TestCC7_2_PassesWhenGCPDurableSinkExports(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	s := gcpSink("audit-to-bq", "bigquery", true, true)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego",
		map[string]any{"resources": []any{s}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC7_2_FailsWhenGCPScannedButNoSinks(t *testing.T) {
	// gcp.* resource present (any kind) but no logging sinks at all
	// — admin audit logs never leave the project.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego",
		map[string]any{"resources": []any{gcpMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail (GCP scanned but no sinks)", d.Status)
	}
}

func TestCC7_2_FailsWhenGCPSinkNotDurable(t *testing.T) {
	// Sink captures admin activity but writes to the in-project
	// _Default logging bucket — not a durable export.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	s := gcpSink("local-only", "logging", true, false)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego",
		map[string]any{"resources": []any{s}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail (sink not durable)", d.Status)
	}
}

func TestCC7_2_FailsWhenGCPSinkExcludesAdminActivity(t *testing.T) {
	// Durable destination but filter excludes admin activity logs.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	s := gcpSink("app-logs-only", "bigquery", false, true)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego",
		map[string]any{"resources": []any{s}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail (sink does not capture admin activity)", d.Status)
	}
}

func TestCC7_2_PassesWithMixedSinks(t *testing.T) {
	// One bad sink + one compliant sink — applicable cloud passes
	// as long as at least one sink is durable + captures admin
	// activity (matches AWS/Azure "any compliant" semantics).
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bad := gcpSink("local-only", "logging", true, false)
	good := gcpSink("audit-to-pubsub", "pubsub", true, true)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_2.rego",
		map[string]any{"resources": []any{bad, good}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
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

// ── CC6.8 + CC7.3 + CC7.1 — Microsoft Defender for Cloud ────────────────────

func defenderPlan(name, tier string) map[string]any {
	return map[string]any{
		"type": "azure.defender.pricing",
		"id":   "/subscriptions/sub/providers/Microsoft.Security/pricings/" + name,
		"attrs": map[string]any{
			"plan_name":       name,
			"subscription_id": "sub",
			"pricing_tier":    tier,
			"enabled":         tier == "Standard",
		},
	}
}

func runDefenderTest(t *testing.T, control string, resources []any, wantStatus string) {
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

func TestCC6_8_PassesWhenDefenderEnabled(t *testing.T) {
	runDefenderTest(t, "soc2_2017/cc6_8.rego",
		[]any{defenderPlan("VirtualMachines", "Standard"), azureMarker()},
		"pass")
}

func TestCC6_8_FailsWhenAllDefenderFree(t *testing.T) {
	runDefenderTest(t, "soc2_2017/cc6_8.rego",
		[]any{defenderPlan("VirtualMachines", "Free"), defenderPlan("StorageAccounts", "Free"), azureMarker()},
		"fail")
}

func TestCC6_8_FailsWhenAzureScannedButNoDefender(t *testing.T) {
	runDefenderTest(t, "soc2_2017/cc6_8.rego",
		[]any{azureMarker()},
		"fail")
}

func TestCC7_3_PassesWhenDefenderEnabled(t *testing.T) {
	runDefenderTest(t, "soc2_2017/cc7_3.rego",
		[]any{defenderPlan("VirtualMachines", "Standard"), azureMarker()},
		"pass")
}

func TestCC7_3_FailsWhenAllDefenderFree(t *testing.T) {
	runDefenderTest(t, "soc2_2017/cc7_3.rego",
		[]any{defenderPlan("VirtualMachines", "Free"), azureMarker()},
		"fail")
}

func TestCC7_1_PassesWhenDefenderEnabled(t *testing.T) {
	runDefenderTest(t, "soc2_2017/cc7_1.rego",
		[]any{defenderPlan("VirtualMachines", "Standard"), azureMarker()},
		"pass")
}

func TestCC7_1_FailsWhenAllDefenderFree(t *testing.T) {
	runDefenderTest(t, "soc2_2017/cc7_1.rego",
		[]any{defenderPlan("VirtualMachines", "Free"), azureMarker()},
		"fail")
}

// Mixed-cloud: AWS Security Hub active but Azure Defender all Free → fail.
func TestCC7_1_MixedFailsOnAzureGap(t *testing.T) {
	awsHub := hubWithStandards("us-east-1", []any{
		"arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.2.0",
	})
	runDefenderTest(t, "soc2_2017/cc7_1.rego",
		[]any{awsHub, awsMarker(), defenderPlan("VirtualMachines", "Free"), azureMarker()},
		"fail")
}

// ── CC7.1 — Security Hub vulnerability detection ────────────────────────────

func hubWithStandards(region string, standards []any) map[string]any {
	return map[string]any{
		"type": "aws.securityhub.hub",
		"id":   "arn:aws:securityhub:" + region + ":123456789012:hub/default",
		"attrs": map[string]any{
			"region":               region,
			"auto_enable_controls": true,
			"subscribed_standards": standards,
		},
	}
}

func TestCC7_1_PassesWhenHubHasStandards(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	hub := hubWithStandards("us-east-1", []any{
		"arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0",
		"arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.2.0",
	})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_1.rego",
		map[string]any{"resources": []any{hub, awsMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC7_1_FailsWhenNoHub(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_1.rego",
		map[string]any{"resources": []any{awsMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail; message=%q", d.Status, d.Message)
	}
}

func TestCC7_1_FailsWhenHubHasNoStandards(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	hub := hubWithStandards("us-east-1", []any{})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_1.rego",
		map[string]any{"resources": []any{hub, awsMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_1_PassesWhenOneRegionActive(t *testing.T) {
	// Hub enabled in us-east-1 with standards; eu-west-1 hub exists
	// but has no standards. CC7.1 only requires ANY region to have an
	// active hub — at least one detection pipeline beats none.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	good := hubWithStandards("us-east-1", []any{
		"arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0",
	})
	empty := hubWithStandards("eu-west-1", []any{})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_1.rego",
		map[string]any{"resources": []any{good, empty, awsMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass", d.Status)
	}
}

func TestCC7_1_NotApplicableWhenNoAWS(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_1.rego",
		map[string]any{"resources": []any{}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// ── CC6.8 + CC7.1 + CC7.3 — GCP Security Command Center ─────────────────────

func gcpSCC(active bool, sources []any) map[string]any {
	return map[string]any{
		"type": "gcp.scc.subscription",
		"id":   "gcp-scc://acme-prod-001/subscription",
		"attrs": map[string]any{
			"project":      "acme-prod-001",
			"is_active":    active,
			"source_count": len(sources),
			"sources":      sources,
		},
	}
}

func runSCCTest(t *testing.T, controlPath string, sub map[string]any, wantStatus string) {
	t.Helper()
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), controlPath,
		map[string]any{"resources": []any{sub}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != wantStatus {
		t.Fatalf("status = %q, want %q; message=%q", d.Status, wantStatus, d.Message)
	}
}

func TestCC6_8_PassesWhenGCPSCCActive(t *testing.T) {
	runSCCTest(t, "soc2_2017/cc6_8.rego",
		gcpSCC(true, []any{"Event Threat Detection", "VM Threat Detection"}),
		"pass")
}

func TestCC6_8_FailsWhenGCPSCCNotActive(t *testing.T) {
	runSCCTest(t, "soc2_2017/cc6_8.rego",
		gcpSCC(false, []any{}),
		"fail")
}

func TestCC7_1_PassesWhenGCPSCCActive(t *testing.T) {
	runSCCTest(t, "soc2_2017/cc7_1.rego",
		gcpSCC(true, []any{"Security Health Analytics"}),
		"pass")
}

func TestCC7_1_FailsWhenGCPSCCNotActive(t *testing.T) {
	runSCCTest(t, "soc2_2017/cc7_1.rego",
		gcpSCC(false, []any{}),
		"fail")
}

func TestCC7_3_PassesWhenGCPSCCActive(t *testing.T) {
	runSCCTest(t, "soc2_2017/cc7_3.rego",
		gcpSCC(true, []any{"Event Threat Detection"}),
		"pass")
}

func TestCC7_3_FailsWhenGCPSCCNotActive(t *testing.T) {
	runSCCTest(t, "soc2_2017/cc7_3.rego",
		gcpSCC(false, []any{}),
		"fail")
}

// ── CC7.5 — RDS recovery procedures ─────────────────────────────────────────

func rdsInstance(id string, backupDays int, deletionProtection bool) map[string]any {
	return map[string]any{
		"type": "aws.rds.db_instance",
		"id":   "arn:aws:rds:us-east-1:123456789012:db:" + id,
		"attrs": map[string]any{
			"db_instance_identifier":     id,
			"engine":                     "postgres",
			"region":                     "us-east-1",
			"backup_retention_period":    backupDays,
			"deletion_protection":        deletionProtection,
			"storage_encrypted":          true,
			"publicly_accessible":        false,
			"auto_minor_version_upgrade": true,
		},
	}
}

// rdsInstanceWithCIS overrides the three CIS Section 2.3 flags on
// top of the rdsInstance defaults. Sweeps test variants for 2.3.1 /
// 2.3.2 / 2.3.3 without duplicating the boilerplate attrs.
func rdsInstanceWithCIS(id string, encrypted, autoUpgrade, publiclyAccessible bool) map[string]any {
	r := rdsInstance(id, 14, true)
	attrs := r["attrs"].(map[string]any)
	attrs["storage_encrypted"] = encrypted
	attrs["auto_minor_version_upgrade"] = autoUpgrade
	attrs["publicly_accessible"] = publiclyAccessible
	return r
}

func TestCC7_5_PassesWhenAllDBsRecoverable(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{rdsInstance("prod", 14, true), rdsInstance("staging", 7, true)}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC7_5_FailsWhenBackupRetentionTooLow(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{rdsInstance("prod", 1, true)}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_5_FailsWhenBackupsDisabled(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{rdsInstance("prod", 0, true)}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_5_FailsWhenNoDeletionProtection(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{rdsInstance("prod", 14, false)}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_5_NotApplicableWhenNoRDS(t *testing.T) {
	// Account has AWS resources but no RDS — CC7.5 is silent rather
	// than failing, because the recovery story for non-RDS data
	// stores is evaluated elsewhere.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{awsMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// ── CC7.5 — Azure SQL ───────────────────────────────────────────────────────

func azureSQLDatabase(name string, retentionDays int) map[string]any {
	return map[string]any{
		"type": "azure.sql.database",
		"id":   "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/srv/databases/" + name,
		"attrs": map[string]any{
			"database_name":           name,
			"server_name":             "srv",
			"subscription_id":         "sub",
			"location":                "eastus",
			"status":                  "Online",
			"backup_retention_period": retentionDays,
		},
	}
}

func TestCC7_5_PassesOnRecoverableAzureSQL(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{azureSQLDatabase("prod-app", 14)}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC7_5_FailsOnLowAzureRetention(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{azureSQLDatabase("prod-app", 1)}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

// Mixed: AWS RDS compliant, Azure SQL not → fail on Azure side.
func TestCC7_5_MixedFailsOnAzureGap(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{rdsInstance("prod-aws", 14, true), azureSQLDatabase("prod-az", 1)}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

// ── CC7.5 — GCP Cloud SQL ───────────────────────────────────────────────────

func gcpSQLInstance(name string, backupEnabled bool, retentionDays int, deletionProt bool) map[string]any {
	return map[string]any{
		"type": "gcp.sql.instance",
		"id":   "gcp-sql://acme-prod-001/instances/" + name,
		"attrs": map[string]any{
			"name":                           name,
			"project":                        "acme-prod-001",
			"database_version":               "POSTGRES_15",
			"state":                          "RUNNABLE",
			"backup_enabled":                 backupEnabled,
			"backup_retention_days":          retentionDays,
			"point_in_time_recovery_enabled": true,
			"deletion_protection":            deletionProt,
		},
	}
}

func TestCC7_5_PassesWhenGCPSQLCompliant(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	inst := gcpSQLInstance("prod-gcp", true, 14, true)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{inst}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC7_5_FailsWhenGCPSQLBackupsDisabled(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	inst := gcpSQLInstance("no-backups", false, 0, true)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{inst}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_5_FailsWhenGCPSQLRetentionTooShort(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	inst := gcpSQLInstance("short-retention", true, 3, true)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{inst}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_5_FailsWhenGCPSQLNoDeletionProtection(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	inst := gcpSQLInstance("no-delprot", true, 14, false)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{inst}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_5_PassesAcrossAllThreeClouds(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_5.rego",
		map[string]any{"resources": []any{
			rdsInstance("prod-aws", 14, true),
			azureSQLDatabase("prod-az", 14),
			gcpSQLInstance("prod-gcp", true, 14, true),
		}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

// ── CC6.2 — GitHub MFA enforcement ──────────────────────────────────────────

func githubOrg(login string, requires2FA bool, membersWithout []any) map[string]any {
	return map[string]any{
		"type": "github.org",
		"id":   "github://orgs/" + login,
		"attrs": map[string]any{
			"login":                          login,
			"two_factor_requirement_enabled": requires2FA,
			"members_without_2fa":            membersWithout,
			"members_without_2fa_count":      len(membersWithout),
		},
	}
}

func TestCC6_2_PassesWhenOrgRequires2FAAndAllMembersHaveIt(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	org := githubOrg("forged-in-feathers", true, []any{})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_2.rego",
		map[string]any{"resources": []any{org}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC6_2_FailsWhenOrgDoesNotRequire2FA(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	org := githubOrg("loose-org", false, []any{})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_2.rego",
		map[string]any{"resources": []any{org}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_2_FailsWhenMembersWithout2FAExist(t *testing.T) {
	// Org has 2FA-required policy but stale members slipped through —
	// e.g. policy enabled after invites went out.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	org := githubOrg("mixed-org", true, []any{"alice", "bob"})
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_2.rego",
		map[string]any{"resources": []any{org}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC6_2_NotApplicableWhenNoGitHub(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc6_2.rego",
		map[string]any{"resources": []any{awsMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// ── CC7.4 — Linear incident response ─────────────────────────────────────────

func linearWorkspace(name string, closedCount, staleCount int, attestNone bool) map[string]any {
	return map[string]any{
		"type": "linear.workspace",
		"id":   "linear://workspaces/" + name,
		"attrs": map[string]any{
			"workspace_name":                   name,
			"incident_labels":                  []any{"security", "incident"},
			"sla_window_days":                  30,
			"attest_no_incidents":              attestNone,
			"security_issues_closed_count":     closedCount,
			"security_issues_open_stale_count": staleCount,
		},
	}
}

func TestCC7_4_PassesWhenClosedTicketInWindow(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ws := linearWorkspace("forged-in-feathers", 2, 0, false)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_4.rego",
		map[string]any{"resources": []any{ws}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC7_4_PassesWhenAttestNoIncidents(t *testing.T) {
	// Zero closed tickets in window is fine if the operator explicitly
	// attests the window was incident-free.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ws := linearWorkspace("calm-quarter", 0, 0, true)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_4.rego",
		map[string]any{"resources": []any{ws}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC7_4_FailsWithNoProofAndNoAttestation(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ws := linearWorkspace("silent-team", 0, 0, false)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_4.rego",
		map[string]any{"resources": []any{ws}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_4_FailsWhenStaleOpenTickets(t *testing.T) {
	// Even a workspace with closed-in-window tickets fails if there
	// are incident-labelled tickets still open past the SLA.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ws := linearWorkspace("backlogged-team", 3, 2, false)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_4.rego",
		map[string]any{"resources": []any{ws}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_4_NotApplicableWhenNoLinear(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_4.rego",
		map[string]any{"resources": []any{awsMarker()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// ── CC7.4 — Jira incident response (parallel source) ────────────────────────

func jiraSite(siteURL string, closedCount, staleCount int, attestNone bool) map[string]any {
	return map[string]any{
		"type": "jira.site",
		"id":   "jira://sites/" + siteURL,
		"attrs": map[string]any{
			"site_url":                         "https://" + siteURL,
			"incident_labels":                  []any{"security", "incident"},
			"sla_window_days":                  30,
			"attest_no_incidents":              attestNone,
			"security_issues_closed_count":     closedCount,
			"security_issues_open_stale_count": staleCount,
		},
	}
}

func TestCC7_4_PassesOnJiraClosedInWindow(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	site := jiraSite("forged.atlassian.net", 4, 0, false)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_4.rego",
		map[string]any{"resources": []any{site}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCC7_4_FailsOnJiraStaleOpen(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	site := jiraSite("backlogged.atlassian.net", 1, 3, false)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_4.rego",
		map[string]any{"resources": []any{site}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_4_FailsWhenLinearPassesButJiraStale(t *testing.T) {
	// Mixed setup: a clean Linear workspace but a Jira site with
	// stale open tickets. The site's finding must surface even when
	// the workspace alone would pass.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ws := linearWorkspace("forged-in-feathers", 2, 0, false)
	site := jiraSite("backlogged.atlassian.net", 0, 1, false)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_4.rego",
		map[string]any{"resources": []any{ws, site}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCC7_4_PassesWhenBothSourcesHealthy(t *testing.T) {
	// Both sources healthy: Linear has closed tickets, Jira has
	// attestation. Either alone would pass; together they still pass.
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ws := linearWorkspace("forged-in-feathers", 1, 0, false)
	site := jiraSite("forged.atlassian.net", 0, 0, true)
	d, err := e.Evaluate(context.Background(), "soc2_2017/cc7_4.rego",
		map[string]any{"resources": []any{ws, site}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

// ── CIS AWS 1.5 — account-level IAM rules (batch 1) ─────────────────────────

func awsAccountSummary(rootKeysPresent, rootMFA bool) map[string]any {
	return map[string]any{
		"type": "aws.iam.account_summary",
		"id":   "aws-iam://account/summary",
		"attrs": map[string]any{
			"root_access_keys_present":   rootKeysPresent,
			"root_mfa_enabled":           rootMFA,
			"root_mfa_virtual":           false,
			"root_signing_certs_present": false,
		},
	}
}

// awsAccountSummaryWithMFAType variant: lets tests specify whether
// root MFA is virtual vs hardware. CIS 1.6 reads this directly.
func awsAccountSummaryWithMFAType(rootMFAEnabled, rootMFAVirtual bool) map[string]any {
	r := awsAccountSummary(false, rootMFAEnabled)
	r["attrs"].(map[string]any)["root_mfa_virtual"] = rootMFAVirtual
	return r
}

// awsCustomerManagedPolicy builds an aws.iam.customer_managed_policy
// resource shaped for CIS 1.16.
func awsCustomerManagedPolicy(name string, attachmentCount int, isAdmin bool) map[string]any {
	return map[string]any{
		"type": "aws.iam.customer_managed_policy",
		"id":   "arn:aws:iam::123456789012:policy/" + name,
		"attrs": map[string]any{
			"policy_name":      name,
			"arn":              "arn:aws:iam::123456789012:policy/" + name,
			"default_version":  "v1",
			"attachment_count": attachmentCount,
			"is_admin":         isAdmin,
		},
	}
}

// awsAccessAnalyzerRegion builds an aws.accessanalyzer.region resource
// shaped for CIS 1.21.
func awsAccessAnalyzerRegion(region string, count int, hasActive bool) map[string]any {
	return map[string]any{
		"type": "aws.accessanalyzer.region",
		"id":   "aws-accessanalyzer://" + region,
		"attrs": map[string]any{
			"region":              region,
			"analyzer_count":      count,
			"has_active_analyzer": hasActive,
		},
	}
}

// awsServerCertificate builds an aws.iam.server_certificate resource.
// Pass expiresIn=0 for "no expiration field". Negative durations
// produce a cert that's already expired.
func awsServerCertificate(name string, expiresIn time.Duration) map[string]any {
	attrs := map[string]any{
		"server_certificate_name": name,
		"path":                    "/",
		"upload_date":             time.Now().Add(-365 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}
	if expiresIn == 0 {
		attrs["expiration"] = nil
	} else {
		attrs["expiration"] = time.Now().Add(expiresIn).UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"type":  "aws.iam.server_certificate",
		"id":    "arn:aws:iam::123456789012:server-certificate/" + name,
		"attrs": attrs,
	}
}

func awsPasswordPolicy(configured bool, minLen, reusePrev int) map[string]any {
	attrs := map[string]any{"configured": configured}
	if configured {
		attrs["minimum_password_length"] = minLen
		attrs["password_reuse_prevention"] = reusePrev
		attrs["require_symbols"] = true
		attrs["require_numbers"] = true
		attrs["require_uppercase_characters"] = true
		attrs["require_lowercase_characters"] = true
		attrs["allow_users_to_change_password"] = true
		attrs["expire_passwords"] = false
		attrs["max_password_age"] = 0
		attrs["hard_expiry"] = false
	}
	return map[string]any{
		"type":  "aws.iam.password_policy",
		"id":    "aws-iam://account/password-policy",
		"attrs": attrs,
	}
}

func evalCIS(t *testing.T, path string, resource map[string]any) string {
	t.Helper()
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), path,
		map[string]any{"resources": []any{resource}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return d.Status
}

// CIS 1.4

func TestCIS_1_4_PassesWhenRootHasNoKeys(t *testing.T) {
	if got := evalCIS(t, "cis_aws_1_5/cis_1_4.rego", awsAccountSummary(false, true)); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_4_FailsWhenRootHasKey(t *testing.T) {
	if got := evalCIS(t, "cis_aws_1_5/cis_1_4.rego", awsAccountSummary(true, true)); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_4_NotApplicableWhenNoAWSScan(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "cis_aws_1_5/cis_1_4.rego",
		map[string]any{"resources": []any{}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// CIS 1.5

func TestCIS_1_5_PassesWhenRootMFAEnabled(t *testing.T) {
	if got := evalCIS(t, "cis_aws_1_5/cis_1_5.rego", awsAccountSummary(false, true)); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_5_FailsWhenRootMFADisabled(t *testing.T) {
	if got := evalCIS(t, "cis_aws_1_5/cis_1_5.rego", awsAccountSummary(false, false)); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

// CIS 1.8

func TestCIS_1_8_PassesWhenMinLengthAtThreshold(t *testing.T) {
	if got := evalCIS(t, "cis_aws_1_5/cis_1_8.rego", awsPasswordPolicy(true, 14, 24)); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_8_FailsWhenMinLengthBelowThreshold(t *testing.T) {
	if got := evalCIS(t, "cis_aws_1_5/cis_1_8.rego", awsPasswordPolicy(true, 8, 24)); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_8_FailsWhenNoPolicyConfigured(t *testing.T) {
	if got := evalCIS(t, "cis_aws_1_5/cis_1_8.rego", awsPasswordPolicy(false, 0, 0)); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

// CIS 1.9

func TestCIS_1_9_PassesWhenReusePreventionAtThreshold(t *testing.T) {
	if got := evalCIS(t, "cis_aws_1_5/cis_1_9.rego", awsPasswordPolicy(true, 14, 24)); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_9_FailsWhenReusePreventionBelowThreshold(t *testing.T) {
	if got := evalCIS(t, "cis_aws_1_5/cis_1_9.rego", awsPasswordPolicy(true, 14, 5)); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_9_FailsWhenNoPolicyConfigured(t *testing.T) {
	if got := evalCIS(t, "cis_aws_1_5/cis_1_9.rego", awsPasswordPolicy(false, 0, 0)); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

// ── CIS AWS 1.5 — user-level IAM rules (batch 2) ────────────────────────────

// awsIAMUser builds a CIS-shaped aws.iam.user resource. lastUsedAgo
// and passwordAgo are durations expressing how long ago each
// timestamp was; passing 0 means "never used" (nil in the attrs).
// createdAgo positions the user (and each key's create_date) far
// enough in the past to push past CIS 1.12's 45-day grace window
// when set to >45 days.
func awsIAMUser(userName string, hasConsole bool, createdAgo, passwordAgo time.Duration, keys []map[string]any) map[string]any {
	var pwLastUsed any
	if hasConsole && passwordAgo > 0 {
		pwLastUsed = time.Now().Add(-passwordAgo).UTC().Format(time.RFC3339)
	}
	keysCopy := make([]any, 0, len(keys))
	for _, k := range keys {
		keysCopy = append(keysCopy, k)
	}
	return map[string]any{
		"type": "aws.iam.user",
		"id":   "arn:aws:iam::123456789012:user/" + userName,
		"attrs": map[string]any{
			"user_name":               userName,
			"create_date":             time.Now().Add(-createdAgo).UTC().Format(time.RFC3339),
			"has_console":             hasConsole,
			"password_last_used":      pwLastUsed,
			"mfa_devices":             []any{},
			"access_keys":             keysCopy,
			"attached_policies_count": 0,
			"inline_policies_count":   0,
		},
	}
}

// awsIAMUserWithDirectPolicies builds a user resource for CIS 1.15
// where the count of directly-attached managed + inline policies is
// non-zero.
func awsIAMUserWithDirectPolicies(userName string, attachedCount, inlineCount int) map[string]any {
	u := awsIAMUser(userName, false, 24*time.Hour, 0, nil)
	u["attrs"].(map[string]any)["attached_policies_count"] = attachedCount
	u["attrs"].(map[string]any)["inline_policies_count"] = inlineCount
	return u
}

// awsSupportAccessSummary builds the aws.iam.support_access_summary
// resource for CIS 1.17. totalAttachments=0 is the failure signal.
func awsSupportAccessSummary(users, groups, roles int) map[string]any {
	return map[string]any{
		"type": "aws.iam.support_access_summary",
		"id":   "aws-iam://account/support-access",
		"attrs": map[string]any{
			"policy_arn":             "arn:aws:iam::aws:policy/AWSSupportAccess",
			"attached_users_count":   users,
			"attached_groups_count":  groups,
			"attached_roles_count":   roles,
			"total_attachment_count": users + groups + roles,
		},
	}
}

// awsIAMAccessKey builds an access key entry shaped for CIS 1.12 /
// 1.13 / 1.14. createdAgo / lastUsedAgo are durations ago; passing
// 0 for lastUsedAgo means "never used".
func awsIAMAccessKey(id, status string, createdAgo, lastUsedAgo time.Duration) map[string]any {
	var lastUsed any
	if lastUsedAgo > 0 {
		lastUsed = time.Now().Add(-lastUsedAgo).UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"access_key_id":  id,
		"status":         status,
		"create_date":    time.Now().Add(-createdAgo).UTC().Format(time.RFC3339),
		"last_used_date": lastUsed,
	}
}

func awsIAMUserWithMFA(userName string, hasConsole bool, mfaSerials []string, keys []map[string]any) map[string]any {
	mfa := make([]any, 0, len(mfaSerials))
	for _, s := range mfaSerials {
		mfa = append(mfa, map[string]any{"serial_number": s})
	}
	u := awsIAMUser(userName, hasConsole, 365*24*time.Hour, 24*time.Hour, keys)
	u["attrs"].(map[string]any)["mfa_devices"] = mfa
	return u
}

// CIS 1.10 — MFA on console users

func TestCIS_1_10_PassesWhenAllConsoleUsersHaveMFA(t *testing.T) {
	u := awsIAMUserWithMFA("alice", true, []string{"arn:aws:iam::1:mfa/alice"}, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_10.rego", u); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_10_FailsWhenConsoleUserMissingMFA(t *testing.T) {
	u := awsIAMUserWithMFA("bob", true, nil, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_10.rego", u); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_10_NotApplicableWhenNoConsoleUsers(t *testing.T) {
	u := awsIAMUserWithMFA("svc", false, nil, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_10.rego", u); got != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", got)
	}
}

// CIS 1.12 — stale credentials

func TestCIS_1_12_PassesOnFreshConsoleAndKey(t *testing.T) {
	// Console used yesterday, key used yesterday → both within window.
	key := awsIAMAccessKey("AKIA1", "Active", 200*24*time.Hour, 24*time.Hour)
	u := awsIAMUser("alice", true, 200*24*time.Hour, 24*time.Hour, []map[string]any{key})
	if got := evalCIS(t, "cis_aws_1_5/cis_1_12.rego", u); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_12_FailsOnStaleConsolePassword(t *testing.T) {
	u := awsIAMUser("bob", true, 200*24*time.Hour, 90*24*time.Hour, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_12.rego", u); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_12_FailsOnNeverUsedConsolePasswordPastGrace(t *testing.T) {
	// Console enabled 100 days ago, never used → fail.
	u := awsIAMUser("ghost", true, 100*24*time.Hour, 0, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_12.rego", u); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_12_PassesOnNeverUsedConsoleInsideGrace(t *testing.T) {
	// Just created — still inside the 45-day grace window.
	u := awsIAMUser("newhire", true, 10*24*time.Hour, 0, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_12.rego", u); got != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", got)
	}
}

func TestCIS_1_12_FailsOnStaleAccessKey(t *testing.T) {
	key := awsIAMAccessKey("AKIA2", "Active", 200*24*time.Hour, 60*24*time.Hour)
	u := awsIAMUser("svc", false, 200*24*time.Hour, 0, []map[string]any{key})
	if got := evalCIS(t, "cis_aws_1_5/cis_1_12.rego", u); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_12_IgnoresInactiveAccessKey(t *testing.T) {
	// Inactive key never used in 200 days — still fine, it's not in
	// circulation.
	key := awsIAMAccessKey("AKIA3", "Inactive", 200*24*time.Hour, 0)
	u := awsIAMUser("svc", false, 200*24*time.Hour, 0, []map[string]any{key})
	if got := evalCIS(t, "cis_aws_1_5/cis_1_12.rego", u); got != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", got)
	}
}

// CIS 1.13 — one active key per user

func TestCIS_1_13_PassesWithSingleActiveKey(t *testing.T) {
	k := awsIAMAccessKey("AKIA1", "Active", 24*time.Hour, 24*time.Hour)
	u := awsIAMUser("alice", false, 24*time.Hour, 0, []map[string]any{k})
	if got := evalCIS(t, "cis_aws_1_5/cis_1_13.rego", u); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_13_FailsWithTwoActiveKeys(t *testing.T) {
	k1 := awsIAMAccessKey("AKIA1", "Active", 24*time.Hour, 24*time.Hour)
	k2 := awsIAMAccessKey("AKIA2", "Active", 24*time.Hour, 24*time.Hour)
	u := awsIAMUser("rotator", false, 24*time.Hour, 0, []map[string]any{k1, k2})
	if got := evalCIS(t, "cis_aws_1_5/cis_1_13.rego", u); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_13_PassesWithOneActiveOneInactive(t *testing.T) {
	// One active, one inactive — within the rule's intent.
	k1 := awsIAMAccessKey("AKIA1", "Active", 24*time.Hour, 24*time.Hour)
	k2 := awsIAMAccessKey("AKIA2", "Inactive", 24*time.Hour, 24*time.Hour)
	u := awsIAMUser("rotator", false, 24*time.Hour, 0, []map[string]any{k1, k2})
	if got := evalCIS(t, "cis_aws_1_5/cis_1_13.rego", u); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

// CIS 1.14 — key rotation within 90 days

func TestCIS_1_14_PassesWithFreshKey(t *testing.T) {
	k := awsIAMAccessKey("AKIA1", "Active", 30*24*time.Hour, 24*time.Hour)
	u := awsIAMUser("alice", false, 30*24*time.Hour, 0, []map[string]any{k})
	if got := evalCIS(t, "cis_aws_1_5/cis_1_14.rego", u); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_14_FailsWithStaleKey(t *testing.T) {
	k := awsIAMAccessKey("AKIA1", "Active", 120*24*time.Hour, 24*time.Hour)
	u := awsIAMUser("legacy", false, 120*24*time.Hour, 0, []map[string]any{k})
	if got := evalCIS(t, "cis_aws_1_5/cis_1_14.rego", u); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_14_IgnoresStaleInactiveKey(t *testing.T) {
	// Inactive keys aren't in circulation; CIS 1.14 only flags Active.
	k := awsIAMAccessKey("AKIA1", "Inactive", 365*24*time.Hour, 0)
	u := awsIAMUser("retired", false, 365*24*time.Hour, 0, []map[string]any{k})
	if got := evalCIS(t, "cis_aws_1_5/cis_1_14.rego", u); got != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", got)
	}
}

// ── CIS AWS 1.5 — Section 1 misc (batch 3) ──────────────────────────────────

// CIS 1.15 — users get permissions only through groups

func TestCIS_1_15_PassesWhenNoDirectPolicies(t *testing.T) {
	u := awsIAMUserWithDirectPolicies("alice", 0, 0)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_15.rego", u); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_15_FailsOnAttachedPolicy(t *testing.T) {
	u := awsIAMUserWithDirectPolicies("bob", 1, 0)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_15.rego", u); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_15_FailsOnInlinePolicy(t *testing.T) {
	u := awsIAMUserWithDirectPolicies("carol", 0, 1)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_15.rego", u); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_15_NotApplicableWithoutUsers(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "cis_aws_1_5/cis_1_15.rego",
		map[string]any{"resources": []any{}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// CIS 1.17 — support role exists

func TestCIS_1_17_PassesWhenPolicyAttachedToAnyPrincipal(t *testing.T) {
	for _, s := range []map[string]any{
		awsSupportAccessSummary(1, 0, 0),
		awsSupportAccessSummary(0, 1, 0),
		awsSupportAccessSummary(0, 0, 1),
	} {
		if got := evalCIS(t, "cis_aws_1_5/cis_1_17.rego", s); got != "pass" {
			t.Fatalf("status = %q, want pass", got)
		}
	}
}

func TestCIS_1_17_FailsWhenNoAttachments(t *testing.T) {
	s := awsSupportAccessSummary(0, 0, 0)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_17.rego", s); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_17_NotApplicableWithoutSummary(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "cis_aws_1_5/cis_1_17.rego",
		map[string]any{"resources": []any{}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// ── CIS AWS 1.5 — Section 1 batch 4 (1.6 + 1.19) ────────────────────────────

// CIS 1.6 — hardware MFA on root

func TestCIS_1_6_PassesWhenRootHasHardwareMFA(t *testing.T) {
	// rootMFAEnabled=true + rootMFAVirtual=false ⇒ hardware MFA.
	r := awsAccountSummaryWithMFAType(true, false)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_6.rego", r); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_6_FailsWhenRootMFAVirtual(t *testing.T) {
	r := awsAccountSummaryWithMFAType(true, true)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_6.rego", r); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_6_FailsWhenRootMFAMissing(t *testing.T) {
	r := awsAccountSummaryWithMFAType(false, false)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_6.rego", r); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

// CIS 1.19 — expired IAM server certificates

func TestCIS_1_19_PassesWhenCertsValid(t *testing.T) {
	c := awsServerCertificate("prod-api", 60*24*time.Hour)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_19.rego", c); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_19_FailsOnExpiredCert(t *testing.T) {
	c := awsServerCertificate("legacy-api", -30*24*time.Hour)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_19.rego", c); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_19_PassesWhenExpirationMissing(t *testing.T) {
	// Legacy uploads with no expiration field — pass rather than panic
	// on a missing timestamp. Defensive against unusual scanner output.
	c := awsServerCertificate("ancient-api", 0)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_19.rego", c); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_19_NotApplicableWhenNoCerts(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "cis_aws_1_5/cis_1_19.rego",
		map[string]any{"resources": []any{}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// ── CIS AWS 1.5 — Section 1 batch 5 (1.16 + 1.21) ───────────────────────────

// CIS 1.16 — no admin "*:*" customer-managed policies attached

func TestCIS_1_16_PassesWhenAdminPolicyUnattached(t *testing.T) {
	// Admin policy exists but is_attached=0 → no risk → pass.
	p := awsCustomerManagedPolicy("LegacyAdmin", 0, true)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_16.rego", p); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_16_PassesWhenAttachedPolicyNotAdmin(t *testing.T) {
	// Attached but non-admin → pass.
	p := awsCustomerManagedPolicy("ReadOnlyS3", 3, false)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_16.rego", p); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_1_16_FailsWhenAdminPolicyAttached(t *testing.T) {
	p := awsCustomerManagedPolicy("BadAdmin", 1, true)
	if got := evalCIS(t, "cis_aws_1_5/cis_1_16.rego", p); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_1_16_NotApplicableWithoutPolicies(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "cis_aws_1_5/cis_1_16.rego",
		map[string]any{"resources": []any{}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// CIS 1.21 — Access Analyzer enabled in every configured region

func TestCIS_1_21_PassesWhenAllRegionsCovered(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "cis_aws_1_5/cis_1_21.rego",
		map[string]any{"resources": []any{
			awsAccessAnalyzerRegion("us-east-1", 1, true),
			awsAccessAnalyzerRegion("eu-west-1", 1, true),
		}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass; message=%q", d.Status, d.Message)
	}
}

func TestCIS_1_21_FailsWhenAnyRegionMissingAnalyzer(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "cis_aws_1_5/cis_1_21.rego",
		map[string]any{"resources": []any{
			awsAccessAnalyzerRegion("us-east-1", 1, true),
			awsAccessAnalyzerRegion("eu-west-1", 0, false),
		}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestCIS_1_21_NotApplicableWithoutAccessAnalyzerScan(t *testing.T) {
	e, err := policy.NewEngine(packs.FS)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := e.Evaluate(context.Background(), "cis_aws_1_5/cis_1_21.rego",
		map[string]any{"resources": []any{}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

// ── CIS AWS 1.5 — Section 2.1 (S3 storage) ──────────────────────────────────

// CIS 2.1.1 — default encryption

func TestCIS_2_1_1_PassesWhenEncryptionOn(t *testing.T) {
	b := awsS3Bucket("prod", true, true, true, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_1_1.rego", b); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_2_1_1_FailsWhenEncryptionOff(t *testing.T) {
	b := awsS3Bucket("prod", false, true, true, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_1_1.rego", b); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

// CIS 2.1.2 — bucket policy denies HTTP

func TestCIS_2_1_2_PassesWhenHTTPSOnly(t *testing.T) {
	b := awsS3Bucket("prod", true, true, true, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_1_2.rego", b); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_2_1_2_FailsWhenHTTPAllowed(t *testing.T) {
	b := awsS3Bucket("prod", true, false, true, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_1_2.rego", b); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

// CIS 2.1.3 — MFA Delete

func TestCIS_2_1_3_PassesWhenMFADeleteEnabled(t *testing.T) {
	b := awsS3Bucket("prod", true, true, true, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_1_3.rego", b); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_2_1_3_FailsWhenMFADeleteDisabled(t *testing.T) {
	b := awsS3Bucket("prod", true, true, false, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_1_3.rego", b); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

// CIS 2.1.5 — Block public access

func TestCIS_2_1_5_PassesWhenBPAFullyEnabled(t *testing.T) {
	b := awsS3Bucket("prod", true, true, true, nil)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_1_5.rego", b); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_2_1_5_FailsWhenAnyBPAFlagDisabled(t *testing.T) {
	bpa := map[string]any{
		"block_public_acls":       true,
		"ignore_public_acls":      false, // the gap
		"block_public_policy":     true,
		"restrict_public_buckets": true,
	}
	b := awsS3Bucket("prod", true, true, true, bpa)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_1_5.rego", b); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_2_1_NotApplicableWhenNoBuckets(t *testing.T) {
	for _, rego := range []string{
		"cis_aws_1_5/cis_2_1_1.rego",
		"cis_aws_1_5/cis_2_1_2.rego",
		"cis_aws_1_5/cis_2_1_3.rego",
		"cis_aws_1_5/cis_2_1_5.rego",
	} {
		e, err := policy.NewEngine(packs.FS)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		d, err := e.Evaluate(context.Background(), rego,
			map[string]any{"resources": []any{}})
		if err != nil {
			t.Fatalf("Evaluate %s: %v", rego, err)
		}
		if d.Status != "not_applicable" {
			t.Fatalf("%s status = %q, want not_applicable", rego, d.Status)
		}
	}
}

// ── CIS AWS 1.5 — Section 2.3 (RDS) ─────────────────────────────────────────

// CIS 2.3.1 — storage_encrypted

func TestCIS_2_3_1_PassesWhenEncrypted(t *testing.T) {
	r := rdsInstanceWithCIS("prod-db", true, true, false)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_3_1.rego", r); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_2_3_1_FailsWhenNotEncrypted(t *testing.T) {
	r := rdsInstanceWithCIS("legacy-db", false, true, false)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_3_1.rego", r); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

// CIS 2.3.2 — auto minor version upgrade

func TestCIS_2_3_2_PassesWhenAutoUpgradeOn(t *testing.T) {
	r := rdsInstanceWithCIS("prod-db", true, true, false)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_3_2.rego", r); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_2_3_2_FailsWhenAutoUpgradeOff(t *testing.T) {
	r := rdsInstanceWithCIS("locked-db", true, false, false)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_3_2.rego", r); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

// CIS 2.3.3 — not publicly accessible

func TestCIS_2_3_3_PassesWhenPrivate(t *testing.T) {
	r := rdsInstanceWithCIS("prod-db", true, true, false)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_3_3.rego", r); got != "pass" {
		t.Fatalf("status = %q, want pass", got)
	}
}

func TestCIS_2_3_3_FailsWhenPubliclyAccessible(t *testing.T) {
	r := rdsInstanceWithCIS("exposed-db", true, true, true)
	if got := evalCIS(t, "cis_aws_1_5/cis_2_3_3.rego", r); got != "fail" {
		t.Fatalf("status = %q, want fail", got)
	}
}

func TestCIS_2_3_NotApplicableWhenNoRDS(t *testing.T) {
	for _, rego := range []string{
		"cis_aws_1_5/cis_2_3_1.rego",
		"cis_aws_1_5/cis_2_3_2.rego",
		"cis_aws_1_5/cis_2_3_3.rego",
	} {
		e, err := policy.NewEngine(packs.FS)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		d, err := e.Evaluate(context.Background(), rego,
			map[string]any{"resources": []any{}})
		if err != nil {
			t.Fatalf("Evaluate %s: %v", rego, err)
		}
		if d.Status != "not_applicable" {
			t.Fatalf("%s status = %q, want not_applicable", rego, d.Status)
		}
	}
}
