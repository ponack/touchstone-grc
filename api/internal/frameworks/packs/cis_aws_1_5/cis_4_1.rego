# CIS AWS 1.5 — 4.1 Ensure a log metric filter and alarm exist for
# unauthorized API calls.
#
# At least one CloudWatch metric filter must (a) capture
# unauthorized-operation / access-denied events from CloudTrail
# logs, (b) feed an alarm, and (c) route the alarm to an SNS topic
# with at least one active subscription.
#
# We token-match the filter pattern rather than parsing it strictly —
# operators copy patterns from CIS verbatim with minor whitespace
# variation, so substring presence is the practical signal.

package cis_aws_1_5.cis_4_1

import rego.v1

filters := [r | some r in input.resources; r.type == "aws.cloudwatch.metric_filter"]

applicable if {
	count(filters) > 0
}

default applicable := false

matches_pattern(p) if {
	contains(p, "UnauthorizedOperation")
	contains(p, "AccessDenied")
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
		"reason":        "no alarmed metric filter detects unauthorized API calls (UnauthorizedOperation / AccessDenied)",
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

message := "A CloudWatch alarm covers unauthorized API calls and notifies an active SNS subscription." if {
	applicable
	count(violations) == 0
}

message := "No CloudWatch alarm covers unauthorized API calls — auditors expect notification on AccessDenied / UnauthorizedOperation." if {
	applicable
	count(violations) > 0
}
