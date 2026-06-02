# HIPAA Security Rule — 164.312(d) Person or Entity Authentication.
#
# Required standard: implement procedures to verify that a person or
# entity seeking access to ePHI is the one claimed.
#
# Touchstone evaluates two signals on AWS:
#
#   - Account password policy meets a strong baseline (length >= 12,
#     reuse_prevention >= 4 — same PCI 8.3.6 baseline; CIS 14/24
#     satisfies both).
#   - Every console-enabled IAM user carries at least one MFA
#     device (mirrors CIS 1.10 / SOC 2 CC6.1 / PCI 8.4.1).

package hipaa_security_rule.rule_164_312_d

import rego.v1

min_length := 12
min_reuse_prevention := 4

policies := [r | some r in input.resources; r.type == "aws.iam.password_policy"]
users := [r | some r in input.resources; r.type == "aws.iam.user"]
console_users := [r | some r in users; r.attrs.has_console == true]

applicable if {
	count(policies) > 0
}
applicable if {
	count(console_users) > 0
}

default applicable := false

# ── Password policy strength ───────────────────────────────────────

violations contains v if {
	some r in policies
	r.attrs.configured != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "no IAM password policy is configured — Person/Entity Authentication has no enforced baseline",
	}
}

violations contains v if {
	some r in policies
	r.attrs.configured == true
	r.attrs.minimum_password_length < min_length
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("password policy length %d is below HIPAA baseline %d", [r.attrs.minimum_password_length, min_length]),
	}
}

violations contains v if {
	some r in policies
	r.attrs.configured == true
	r.attrs.password_reuse_prevention < min_reuse_prevention
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("password reuse prevention %d is below HIPAA baseline %d", [r.attrs.password_reuse_prevention, min_reuse_prevention]),
	}
}

# ── MFA on console users ───────────────────────────────────────────

violations contains v if {
	some r in console_users
	count(r.attrs.mfa_devices) == 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("console-enabled IAM user %q has no MFA device", [r.attrs.user_name]),
	}
}

default status := "not_applicable"
default message := "No identity / password-policy resources in scan input."
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

message := "Strong Person/Entity Authentication is enforced on every audited identity." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d authentication finding(s) — strong identity controls are incomplete.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
