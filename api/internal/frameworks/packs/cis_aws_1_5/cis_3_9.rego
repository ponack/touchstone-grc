# CIS AWS 1.5 — 3.9 Ensure VPC flow logging is enabled in all VPCs.
#
# Every aws.ec2.vpc resource in scan input must have at least one
# ACTIVE VPC-scoped flow log. The scanner pre-computes
# flow_logs_active so the rego inspects a single boolean.
#
# Subnet-scoped and ENI-scoped flow logs do not count — CIS expects
# coverage at the VPC level.

package cis_aws_1_5.cis_3_9

import rego.v1

vpcs := [r | some r in input.resources; r.type == "aws.ec2.vpc"]

applicable if {
	count(vpcs) > 0
}

default applicable := false

violations contains v if {
	some r in vpcs
	r.attrs.flow_logs_active != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("VPC %q has no ACTIVE flow log", [r.attrs.vpc_id]),
	}
}

default status := "not_applicable"
default message := "No VPCs in scan input."
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

message := sprintf("All %d VPC(s) have flow logging enabled.", [count(vpcs)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d VPC(s) without active flow logs.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
