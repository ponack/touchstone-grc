# CIS AWS 1.5 — 1.8 IAM password policy requires minimum length of 14
# or greater.
#
# The account password policy must require at least 14 characters for
# IAM user passwords. An unconfigured password policy fails the rule
# (the implicit default policy is far weaker than CIS asks for).

package cis_aws_1_5.cis_1_8

import rego.v1

min_length := 14

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
	r.attrs.minimum_password_length < min_length
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("minimum_password_length is %d; CIS requires %d or greater", [r.attrs.minimum_password_length, min_length]),
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

message := sprintf("Password policy enforces minimum length >= %d.", [min_length]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d password policy finding(s).", [count(violations)]) if {
	applicable
	count(violations) > 0
}
