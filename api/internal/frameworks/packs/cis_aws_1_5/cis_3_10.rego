# CIS AWS 1.5 — 3.10 Ensure that Object-level logging for write
# events is enabled for S3 bucket.
#
# At least one CloudTrail trail must have a data-event selector that
# captures S3 object WRITE events account-wide. The scanner
# pre-computes the boolean logs_s3_writes per trail.
#
# AdvancedEventSelectors (the newer API form) is not yet checked —
# tracked as a follow-up. v0 evaluates the classic EventSelectors
# only, which still cover the majority of deployments.

package cis_aws_1_5.cis_3_10

import rego.v1

trails := [r | some r in input.resources; r.type == "aws.cloudtrail.trail"]

applicable if {
	count(trails) > 0
}

default applicable := false

has_trail_logging_writes if {
	some t in trails
	t.attrs.logs_s3_writes == true
}

violations contains v if {
	applicable
	not has_trail_logging_writes
	v := {
		"resource_type": "aws.cloudtrail",
		"resource_id":   "(account)",
		"reason":        "no CloudTrail trail logs S3 object-level WRITE events account-wide",
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

message := "At least one CloudTrail trail captures S3 object-level WRITE events." if {
	applicable
	count(violations) == 0
}

message := "No CloudTrail trail captures S3 object-level WRITE events." if {
	applicable
	count(violations) > 0
}
