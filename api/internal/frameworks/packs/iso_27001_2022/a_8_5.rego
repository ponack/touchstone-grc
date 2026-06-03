# ISO/IEC 27001:2022 Annex A — A.8.5 Secure authentication.
#
# Secure authentication technologies and procedures shall be
# implemented based on access restrictions and the topic-specific
# policy on access control.
#
# Touchstone evaluates two signals on AWS:
#
#   - Account password policy meets a strong baseline
#     (length >= 12, reuse_prevention >= 4 — same PCI 8.3.6
#     baseline; CIS 14/24 satisfies both).
#   - Every console-enabled IAM user carries at least one MFA
#     device (mirrors CIS 1.10 / SOC 2 CC6.1 / PCI 8.4.1 /
#     HIPAA 164.312(d)).

package iso_27001_2022.a_8_5

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

violations contains v if {
	some r in policies
	r.attrs.configured != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "no IAM password policy is configured — secure authentication has no enforced baseline",
	}
}

violations contains v if {
	some r in policies
	r.attrs.configured == true
	r.attrs.minimum_password_length < min_length
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("password policy length %d is below ISO baseline %d", [r.attrs.minimum_password_length, min_length]),
	}
}

violations contains v if {
	some r in policies
	r.attrs.configured == true
	r.attrs.password_reuse_prevention < min_reuse_prevention
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("password reuse prevention %d is below ISO baseline %d", [r.attrs.password_reuse_prevention, min_reuse_prevention]),
	}
}

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

message := "Strong authentication is enforced on every audited identity." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d authentication finding(s) — secure-authentication controls are incomplete.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
