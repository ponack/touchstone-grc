# PCI DSS v4.0 — 7.2.5 Application and system accounts and the
# privileges assigned are managed.
#
# PCI expects every system / application identity to follow least
# privilege. Touchstone evaluates this against two evidence streams:
#
#   AWS IAM users   — direct managed or inline policies are
#                      anti-pattern; permissions should flow through
#                      group membership only (mirrors CIS 1.15).
#   GCP service     — user-managed keys must be rotated within 365
#   accounts           days (mirrors SOC 2 CC6.3 for GCP).

package pci_dss_v4.req_7_2_5

import rego.v1

stale_age_seconds := 365 * 24 * 60 * 60

now_ns := time.now_ns()

iam_users := [r | some r in input.resources; r.type == "aws.iam.user"]
gcp_sas := [r | some r in input.resources; r.type == "gcp.iam.service_account"]

applicable if {
	count(iam_users) > 0
}
applicable if {
	count(gcp_sas) > 0
}

default applicable := false

# ── AWS IAM users: no direct policy attachments ────────────────────

violations contains v if {
	some r in iam_users
	r.attrs.attached_policies_count > 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("IAM user %q has %d managed policy attached directly", [r.attrs.user_name, r.attrs.attached_policies_count]),
	}
}

violations contains v if {
	some r in iam_users
	r.attrs.inline_policies_count > 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("IAM user %q has %d inline policy attached directly", [r.attrs.user_name, r.attrs.inline_policies_count]),
	}
}

# ── GCP SA keys: rotation within 365 days ──────────────────────────

violations contains v if {
	some r in gcp_sas
	some k in r.attrs.keys
	k.key_type == "USER_MANAGED"
	age_seconds := (now_ns - time.parse_rfc3339_ns(k.valid_after_time)) / 1000000000
	age_seconds > stale_age_seconds
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("user-managed key %v on service account %v is older than 365 days", [k.id, r.attrs.email]),
	}
}

# ── Outputs ────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No system / application accounts in scan input."
default failures := []

failures := [v | some v in violations]

status := "pass" if {
	applicable
	count(violations) == 0
}

status := "fail" if {
	applicable
	count(violations) > 0
}

message := "Every observable system / application account follows least privilege." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d account-privilege finding(s).", [count(violations)]) if {
	applicable
	count(violations) > 0
}
