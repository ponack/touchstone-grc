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

// ── CC7.5 — RDS recovery procedures ─────────────────────────────────────────

func rdsInstance(id string, backupDays int, deletionProtection bool) map[string]any {
	return map[string]any{
		"type": "aws.rds.db_instance",
		"id":   "arn:aws:rds:us-east-1:123456789012:db:" + id,
		"attrs": map[string]any{
			"db_instance_identifier":  id,
			"engine":                  "postgres",
			"region":                  "us-east-1",
			"backup_retention_period": backupDays,
			"deletion_protection":     deletionProtection,
			"storage_encrypted":       true,
		},
	}
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
