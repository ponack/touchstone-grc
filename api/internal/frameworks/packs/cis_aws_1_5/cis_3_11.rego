# CIS AWS 1.5 — 3.11 Ensure that Object-level logging for read
# events is enabled for S3 bucket.
#
# Mirror of 3.10 for READ events. At least one trail must capture
# S3 object-level reads account-wide.

package cis_aws_1_5.cis_3_11

import rego.v1

trails := [r | some r in input.resources; r.type == "aws.cloudtrail.trail"]

applicable if {
	count(trails) > 0
}

default applicable := false

has_trail_logging_reads if {
	some t in trails
	t.attrs.logs_s3_reads == true
}

violations contains v if {
	applicable
	not has_trail_logging_reads
	v := {
		"resource_type": "aws.cloudtrail",
		"resource_id":   "(account)",
		"reason":        "no CloudTrail trail logs S3 object-level READ events account-wide",
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

message := "At least one CloudTrail trail captures S3 object-level READ events." if {
	applicable
	count(violations) == 0
}

message := "No CloudTrail trail captures S3 object-level READ events." if {
	applicable
	count(violations) > 0
}
