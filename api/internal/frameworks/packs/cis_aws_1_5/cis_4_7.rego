# CIS AWS 1.5 — 4.7 Ensure a log metric filter and alarm exist for
# disabling or scheduled deletion of customer-managed CMKs.
#
# Filter pattern must capture DisableKey + ScheduleKeyDeletion
# events. Token-match: filter contains both event names. CMK
# tampering precedes data-destruction attacks; the alarm gives
# operators a window to intervene during the 7-30 day deletion grace.

package cis_aws_1_5.cis_4_7

import rego.v1

filters := [r | some r in input.resources; r.type == "aws.cloudwatch.metric_filter"]

applicable if {
	count(filters) > 0
}

default applicable := false

matches_pattern(p) if {
	contains(p, "DisableKey")
	contains(p, "ScheduleKeyDeletion")
}

has_compliant_filter if {
	some f in filters
	matches_pattern(f.attrs.filter_pattern)
	f.attrs.has_alarm == true
	f.attrs.has_active_subscription == true
}

violations contains v if {
	applicable
	not has_compliant_filter
	v := {
		"resource_type": "aws.cloudwatch",
		"resource_id":   "(account)",
		"reason":        "no alarmed metric filter detects CMK disable / scheduled-deletion events",
	}
}

default status := "not_applicable"
default message := "No CloudWatch metric filters in scan input."
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

message := "A CloudWatch alarm catches CMK disable / scheduled-deletion events." if {
	applicable
	count(violations) == 0
}

message := "No CloudWatch alarm catches CMK disable / scheduled-deletion events — data-destruction precursor goes unobserved." if {
	applicable
	count(violations) > 0
}
