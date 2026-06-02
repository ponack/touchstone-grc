# HIPAA Security Rule — 164.312(c)(2) Mechanism to Authenticate
# Electronic Protected Health Information.
#
# Addressable implementation specification under the Integrity
# standard §164.312(c)(1). Covered entities must implement
# electronic mechanisms to corroborate that ePHI has not been
# altered or destroyed in an unauthorized manner.
#
# Touchstone evaluates CloudTrail log file validation — every trail
# must have validation enabled so per-hour digests catch tampering
# with the underlying log objects. Same evidence as CIS 3.2.

package hipaa_security_rule.rule_164_312_c_2

import rego.v1

trails := [r | some r in input.resources; r.type == "aws.cloudtrail.trail"]

applicable if {
	count(trails) > 0
}

default applicable := false

violations contains v if {
	some t in trails
	t.attrs.log_file_validation_enabled != true
	v := {
		"resource_type": t.type,
		"resource_id":   t.id,
		"reason":        sprintf("CloudTrail trail %q does not have log file validation enabled — ePHI activity logs may be silently altered", [t.attrs.name]),
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

message := sprintf("All %d CloudTrail trail(s) have log file validation enabled.", [count(trails)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d CloudTrail trail(s) without log file validation — ePHI integrity controls are incomplete.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
