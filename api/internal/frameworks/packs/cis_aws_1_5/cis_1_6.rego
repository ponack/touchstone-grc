# CIS AWS 1.5 — 1.6 Ensure hardware MFA is enabled for the 'root' user
# account.
#
# CIS 1.5 already enforces "any MFA" on root. CIS 1.6 tightens that
# to *hardware* MFA — virtual MFA does not satisfy this rule.
#
# Scanner-side: aws.iam.account_summary carries root_mfa_enabled
# (any kind) plus root_mfa_virtual (true when the root user is bound
# to a virtual MFA device). Hardware MFA = enabled AND not virtual.

package cis_aws_1_5.cis_1_6

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
		"reason":        "the root user has no MFA enabled (CIS 1.6 requires hardware MFA)",
	}
}

violations contains v if {
	some r in summaries
	r.attrs.root_mfa_enabled == true
	r.attrs.root_mfa_virtual == true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "the root user has virtual MFA configured; CIS 1.6 requires hardware MFA",
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

message := "Root user is protected by a hardware MFA device." if {
	applicable
	count(violations) == 0
}

message := "Root MFA does not meet the hardware-only baseline." if {
	applicable
	count(violations) > 0
}
