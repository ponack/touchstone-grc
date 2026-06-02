# HIPAA Security Rule — 164.312(b) Audit Controls.
#
# Required standard: implement hardware, software, and/or procedural
# mechanisms that record and examine activity in information systems
# that contain or use ePHI.
#
# Touchstone evaluates AWS CloudTrail — at least one trail must be
# multi-region AND actively logging AND include global service
# events. Same evidence as CIS 3.1 / PCI 10.2.1.

package hipaa_security_rule.rule_164_312_b

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
		"reason":        "no multi-region CloudTrail trail is actively logging with include_global_service_events — audit-log coverage of ePHI activity is incomplete",
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

message := "At least one CloudTrail trail captures account-wide activity affecting ePHI." if {
	applicable
	count(violations) == 0
}

message := "No multi-region CloudTrail trail is logging — HIPAA audit controls are not satisfied." if {
	applicable
	count(violations) > 0
}
