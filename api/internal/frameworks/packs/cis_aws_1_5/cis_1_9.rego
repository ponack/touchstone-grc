# CIS AWS 1.5 — 1.9 IAM password policy prevents password reuse.
#
# The account password policy must remember at least the last 24
# passwords and refuse to let a user re-set any of them. An
# unconfigured password policy fails the rule.

package cis_aws_1_5.cis_1_9

import rego.v1

min_reuse_prevention := 24

policies := [r | some r in input.resources; r.type == "aws.iam.password_policy"]

applicable if {
	count(policies) > 0
}

default applicable := false

violations contains v if {
	some r in policies
	r.attrs.configured != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "no IAM password policy is configured",
	}
}

violations contains v if {
	some r in policies
	r.attrs.configured == true
	r.attrs.password_reuse_prevention < min_reuse_prevention
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("password_reuse_prevention is %d; CIS requires %d or greater", [r.attrs.password_reuse_prevention, min_reuse_prevention]),
	}
}

default status := "not_applicable"
default message := "No IAM password policy resource in scan input."
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

message := sprintf("Password policy prevents reuse of the last %d passwords or more.", [min_reuse_prevention]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d password reuse finding(s).", [count(violations)]) if {
	applicable
	count(violations) > 0
}
