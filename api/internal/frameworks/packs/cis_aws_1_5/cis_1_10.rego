# CIS AWS 1.5 — 1.10 Ensure multi-factor authentication (MFA) is
# enabled for all IAM users that have a console password.
#
# Same evidence shape as SOC 2 CC6.1's AWS surface; CIS frames it as
# a per-user check (every console-enabled user must carry at least
# one MFA device). Programmatic-only users are out of scope —
# they're covered by access-key rules.
#
# Applicability fires once any aws.iam.user with a console password
# is present in scan input.

package cis_aws_1_5.cis_1_10

import rego.v1

users := [r | some r in input.resources; r.type == "aws.iam.user"]

console_users := [r | some r in users; r.attrs.has_console == true]

applicable if {
	count(console_users) > 0
}

default applicable := false

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
default message := "No console-enabled IAM users in scan input."
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

message := sprintf("All %d console-enabled IAM user(s) carry an MFA device.", [count(console_users)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d console-enabled IAM user(s) without MFA.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
