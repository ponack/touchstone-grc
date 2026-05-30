# CIS AWS 1.5 — 3.2 Ensure CloudTrail log file validation is enabled.
#
# Log file validation generates a per-hour digest file CloudTrail
# signs, so tampering with the underlying log objects becomes
# detectable. Every trail must have it on.

package cis_aws_1_5.cis_3_2

import rego.v1

trails := [r | some r in input.resources; r.type == "aws.cloudtrail.trail"]

applicable if {
	count(trails) > 0
}

default applicable := false

violations contains v if {
	some t in trails
	t.attrs.log_file_validation_enabled != true
	v := {
		"resource_type": t.type,
		"resource_id":   t.id,
		"reason":        sprintf("CloudTrail trail %q does not have log file validation enabled", [t.attrs.name]),
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

message := sprintf("All %d CloudTrail trail(s) have log file validation enabled.", [count(trails)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d CloudTrail trail(s) without log file validation.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
