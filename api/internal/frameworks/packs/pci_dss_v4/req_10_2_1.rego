# PCI DSS v4.0 — 10.2.1 Audit logs enabled and active for all
# system components.
#
# At least one CloudTrail trail must be multi-region AND actively
# logging AND include global service events. Single-region trails
# leave the account partially uncovered; "enabled but not logging"
# trails capture config drift without events.
#
# Same evidence as CIS 3.1.

package pci_dss_v4.req_10_2_1

import rego.v1

trails := [r | some r in input.resources; r.type == "aws.cloudtrail.trail"]

applicable if {
	count(trails) > 0
}

default applicable := false

has_full_region_trail if {
	some t in trails
	t.attrs.is_multi_region == true
	t.attrs.is_logging == true
	t.attrs.include_global_service_events == true
}

violations contains v if {
	applicable
	not has_full_region_trail
	v := {
		"resource_type": "aws.cloudtrail",
		"resource_id":   "(account)",
		"reason":        "no multi-region CloudTrail trail is actively logging with include_global_service_events",
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

message := "At least one multi-region CloudTrail trail captures all account activity." if {
	applicable
	count(violations) == 0
}

message := "No multi-region CloudTrail trail is logging — audit-log coverage is incomplete." if {
	applicable
	count(violations) > 0
}
