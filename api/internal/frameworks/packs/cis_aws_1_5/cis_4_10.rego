# CIS AWS 1.5 — 4.10 Ensure a log metric filter and alarm exist for
# security group changes.
#
# Filter pattern must capture ingress / egress mutations. Token-
# match: filter contains both AuthorizeSecurityGroupIngress and
# RevokeSecurityGroupIngress — the two events most likely to widen
# or close the network perimeter.

package cis_aws_1_5.cis_4_10

import rego.v1

filters := [r | some r in input.resources; r.type == "aws.cloudwatch.metric_filter"]

applicable if {
	count(filters) > 0
}

default applicable := false

matches_pattern(p) if {
	contains(p, "AuthorizeSecurityGroupIngress")
	contains(p, "RevokeSecurityGroupIngress")
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
		"reason":        "no alarmed metric filter detects security group changes",
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

message := "A CloudWatch alarm catches security group changes." if {
	applicable
	count(violations) == 0
}

message := "No CloudWatch alarm catches security group changes — perimeter mutations would go unnoticed." if {
	applicable
	count(violations) > 0
}
