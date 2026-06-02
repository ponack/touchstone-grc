# PCI DSS v4.0 — 8.3.6 Minimum level of complexity for passwords.
#
# Passwords must enforce length and reuse-prevention complexity.
# Touchstone evaluates the AWS account password policy:
#
#   - minimum_password_length >= 12 (PCI v4.0 baseline; CIS picks
#     14 — Touchstone uses CIS's stricter floor since both frameworks
#     read the same evidence and 14 satisfies both).
#   - password_reuse_prevention >= 4 (PCI v4.0 baseline; CIS picks
#     24 — same reasoning).
#
# An unconfigured password policy fails the rule (the implicit
# default is weaker than PCI requires).

package pci_dss_v4.req_8_3_6

import rego.v1

min_length := 12
min_reuse_prevention := 4

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
		"reason":        sprintf("password policy length %d is below PCI baseline %d", [r.attrs.minimum_password_length, min_length]),
	}
}

violations contains v if {
	some r in policies
	r.attrs.configured == true
	r.attrs.password_reuse_prevention < min_reuse_prevention
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("password reuse prevention %d is below PCI baseline %d", [r.attrs.password_reuse_prevention, min_reuse_prevention]),
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

message := sprintf("Password policy meets PCI complexity baseline (length >= %d, reuse >= %d).", [min_length, min_reuse_prevention]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d password complexity finding(s).", [count(violations)]) if {
	applicable
	count(violations) > 0
}
