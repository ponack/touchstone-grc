# CIS AWS 1.5 — 3.4 Ensure CloudTrail trails are integrated with
# CloudWatch Logs.
#
# Integrating with CloudWatch Logs enables real-time alerting on
# CloudTrail events. Every trail must have a CloudWatch Logs log
# group configured — the cloudwatch_logs_log_group_arn attribute
# must be non-empty.

package cis_aws_1_5.cis_3_4

import rego.v1

trails := [r | some r in input.resources; r.type == "aws.cloudtrail.trail"]

applicable if {
	count(trails) > 0
}

default applicable := false

violations contains v if {
	some t in trails
	t.attrs.cloudwatch_logs_log_group_arn == ""
	v := {
		"resource_type": t.type,
		"resource_id":   t.id,
		"reason":        sprintf("CloudTrail trail %q has no CloudWatch Logs log group configured", [t.attrs.name]),
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

message := sprintf("All %d CloudTrail trail(s) ship events to CloudWatch Logs.", [count(trails)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d CloudTrail trail(s) without CloudWatch Logs integration.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
