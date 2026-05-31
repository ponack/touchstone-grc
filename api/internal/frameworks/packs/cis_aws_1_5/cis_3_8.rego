# CIS AWS 1.5 — 3.8 Ensure rotation for customer created CMKs is
# enabled.
#
# Customer-managed symmetric KMS keys must have automatic rotation
# enabled. The scanner pre-computes rotation_applicable (true only
# for symmetric CMKs — rotation isn't supported on asymmetric / HMAC
# keys, so they pass quietly) and rotation_enabled.
#
# AWS-managed keys are filtered at the scanner — they auto-rotate
# every year and are not in scope.

package cis_aws_1_5.cis_3_8

import rego.v1

keys := [r | some r in input.resources; r.type == "aws.kms.key"]

applicable if {
	count(keys) > 0
}

default applicable := false

violations contains v if {
	some r in keys
	r.attrs.enabled == true
	r.attrs.rotation_applicable == true
	r.attrs.rotation_enabled != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("KMS CMK %q does not have automatic rotation enabled", [r.attrs.key_id]),
	}
}

default status := "not_applicable"
default message := "No customer-managed KMS keys in scan input."
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

message := sprintf("All eligible KMS CMK(s) have automatic rotation enabled (%d enumerated).", [count(keys)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d KMS CMK(s) without automatic rotation.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
