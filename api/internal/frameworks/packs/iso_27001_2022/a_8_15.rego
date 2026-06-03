# ISO/IEC 27001:2022 Annex A — A.8.15 Logging.
#
# Logs that record activities, exceptions, faults and other relevant
# events shall be produced, stored, protected and analyzed.
#
# Touchstone evaluates AWS CloudTrail — at least one trail must be
# multi-region AND actively logging AND include global service
# events. Same evidence as CIS 3.1 / PCI 10.2.1 / HIPAA 164.312(b).

package iso_27001_2022.a_8_15

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
		"reason":        "no multi-region CloudTrail trail is actively logging with include_global_service_events — account-wide event logging is incomplete",
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

message := "At least one CloudTrail trail captures account-wide activity." if {
	applicable
	count(violations) == 0
}

message := "No multi-region CloudTrail trail is logging — account-wide activity logging is not in place." if {
	applicable
	count(violations) > 0
}
