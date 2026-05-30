# CIS AWS 1.5 — 1.5 Ensure MFA is enabled for the 'root' user account.
#
# The root user must require multi-factor authentication. Virtual MFA
# satisfies this rule; CIS 1.6 (hardware MFA only) is a stricter
# follow-up that requires distinguishing device types — a future
# scanner enhancement.

package cis_aws_1_5.cis_1_5

import rego.v1

summaries := [r | some r in input.resources; r.type == "aws.iam.account_summary"]

applicable if {
	count(summaries) > 0
}

default applicable := false

violations contains v if {
	some r in summaries
	r.attrs.root_mfa_enabled != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "the root user does not have MFA enabled",
	}
}

default status := "not_applicable"
default message := "No AWS account summary in scan input."
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

message := "Root user has MFA enabled." if {
	applicable
	count(violations) == 0
}

message := "Root user does not have MFA enabled — enable it before any other hardening." if {
	applicable
	count(violations) > 0
}
