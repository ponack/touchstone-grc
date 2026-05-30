# CIS AWS 1.5 — 3.1 Ensure CloudTrail is enabled in all regions.
#
# At least one CloudTrail trail must be multi-region AND actively
# logging AND include global service events. Single-region trails
# leave gaps; "enabled but not logging" trails accumulate config
# without capturing events.
#
# Same evidence as SOC 2 CC7.2 — CIS frames it as a single
# pass/fail rather than "all trails must be compliant".

package cis_aws_1_5.cis_3_1

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

message := "No multi-region CloudTrail trail is logging — large auditable gaps in the account." if {
	applicable
	count(violations) > 0
}
