# CIS AWS 1.5 — 3.7 Ensure CloudTrail logs are encrypted at rest
# using KMS CMKs.
#
# Default S3 encryption (SSE-S3) is not enough for CIS — the trail
# itself must reference a KMS Customer Master Key so log objects
# encrypt with a key the operator controls (and can audit). The
# scanner emits kms_key_id from the trail config; non-empty means a
# CMK is bound.

package cis_aws_1_5.cis_3_7

import rego.v1

trails := [r | some r in input.resources; r.type == "aws.cloudtrail.trail"]

applicable if {
	count(trails) > 0
}

default applicable := false

violations contains v if {
	some t in trails
	t.attrs.kms_key_id == ""
	v := {
		"resource_type": t.type,
		"resource_id":   t.id,
		"reason":        sprintf("CloudTrail trail %q is not configured with a KMS CMK", [t.attrs.name]),
	}
}

default status := "not_applicable"
default message := "No CloudTrail trails in scan input."
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

message := sprintf("All %d CloudTrail trail(s) encrypt log files with a KMS CMK.", [count(trails)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d CloudTrail trail(s) without KMS CMK encryption.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
