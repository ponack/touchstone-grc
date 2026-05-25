# SOC 2 2017 — CC6.1 Logical and physical access controls.
#
# Rule: every IAM user that can log into the AWS console must have at
# least one MFA device. Service accounts without console access are
# out of scope for this check.

package soc2_2017.cc6_1

import rego.v1

# Set of users with console access but no MFA device.
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

# True if the scan produced any IAM users at all.
applicable if {
	some r in input.resources
	r.type == "aws.iam.user"
}

default applicable := false

# ── Outputs ──────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No IAM users in scan input."
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

message := sprintf("%d IAM user(s) with console access lack MFA.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "All console-enabled IAM users have MFA configured." if {
	applicable
	count(violations) == 0
}
