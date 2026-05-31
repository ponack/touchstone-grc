# CIS AWS 1.5 — 4.3 Ensure a log metric filter and alarm exist for
# usage of the 'root' account.
#
# Filter pattern must capture events where userIdentity.type is
# "Root". Token-match: filter contains both "userIdentity.type" and
# "Root" (with the quoting CIS recommends).

package cis_aws_1_5.cis_4_3

import rego.v1

filters := [r | some r in input.resources; r.type == "aws.cloudwatch.metric_filter"]

applicable if {
	count(filters) > 0
}

default applicable := false

matches_pattern(p) if {
	contains(p, "userIdentity.type")
	contains(p, "Root")
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
		"reason":        "no alarmed metric filter detects root account usage",
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

message := "A CloudWatch alarm catches root account usage." if {
	applicable
	count(violations) == 0
}

message := "No CloudWatch alarm catches root account usage — root activity should be exceptional and alerted on." if {
	applicable
	count(violations) > 0
}
