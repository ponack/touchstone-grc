# CIS AWS 1.5 — 2.2.1 Ensure EBS volume encryption is enabled in all
# regions.
#
# The flag is account+region-scoped: when enabled, every new EBS
# volume created in that region is encrypted regardless of the
# creator's intent. CIS expects this on in every region the operator
# uses. Existing unencrypted volumes are not retroactively
# encrypted — they're surfaced by other rules.

package cis_aws_1_5.cis_2_2_1

import rego.v1

regions := [r | some r in input.resources; r.type == "aws.ec2.ebs_encryption_region"]

applicable if {
	count(regions) > 0
}

default applicable := false

violations contains v if {
	some r in regions
	r.attrs.enabled != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("region %q does not have EBS encryption enabled by default", [r.attrs.region]),
	}
}

default status := "not_applicable"
default message := "No EBS encryption region resources in scan input."
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

message := sprintf("All %d configured region(s) enable EBS encryption by default.", [count(regions)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d region(s) accept unencrypted EBS volume creation.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
