# SOC 2 2017 — CC6.1 Logical and physical access controls.
#
# Evaluates MFA enforcement across multiple identity providers:
#
#   AWS IAM users        — has_console + no MFA device → violation
#   Azure AD users       — enabled + MFA-capable but not registered → violation
#   GCP Workspace users  — not suspended + not enrolled in 2-Step Verification → violation
#
# Each cloud's identity surface is its own ruleset; absence of one
# cloud's resources doesn't suppress the others. The control becomes
# applicable once any supported identity-resource is present in
# scan input.

package soc2_2017.cc6_1

import rego.v1

# ── AWS IAM users ───────────────────────────────────────────────────

violations contains v if {
	some r in input.resources
	r.type == "aws.iam.user"
	r.attrs.has_console == true
	count(r.attrs.mfa_devices) == 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "console-enabled IAM user has no MFA device",
	}
}

# ── Azure AD users ──────────────────────────────────────────────────
# Service-principal / guest accounts often legitimately lack MFA, so
# the rule narrows to user_type == "Member" + is_mfa_capable == true.
# is_mfa_capable means the tenant licensing supports MFA for this
# user — so "capable but not registered" is a real gap, while
# "not capable" is a tenant-level licensing decision out of scope.

violations contains v if {
	some r in input.resources
	r.type == "azure.ad.user"
	r.attrs.user_type == "Member"
	r.attrs.is_mfa_capable == true
	r.attrs.is_mfa_registered != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "Azure AD member is MFA-capable but has not registered any MFA method",
	}
}

# ── GCP Workspace users ─────────────────────────────────────────────
# Suspended accounts can't authenticate, so they're excluded from
# the rule. Every active user must be enrolled in 2-Step Verification
# (2SV). is_enforced_2sv is captured for context but not part of the
# pass criterion — enforcement is a Workspace policy lever, while
# enrolment is the per-user signal that proves the lever works.

violations contains v if {
	some r in input.resources
	r.type == "gcp.iam.user"
	r.attrs.suspended != true
	r.attrs.is_enrolled_2sv != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "GCP Workspace user is active but not enrolled in 2-Step Verification",
	}
}

# ── Applicability ───────────────────────────────────────────────────

applicable if {
	some r in input.resources
	r.type == "aws.iam.user"
}
applicable if {
	some r in input.resources
	r.type == "azure.ad.user"
}
applicable if {
	some r in input.resources
	r.type == "gcp.iam.user"
}

default applicable := false

# ── Outputs ─────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No identity resources in scan input."
default failures := []

failures := [v | some v in violations]

status := "fail" if {
	applicable
	count(violations) > 0
}

status := "pass" if {
	applicable
	count(violations) == 0
}

message := sprintf("%d MFA finding(s) across configured identity providers.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "All applicable users have MFA configured." if {
	applicable
	count(violations) == 0
}
