# CIS AWS 1.5 — 5.3 Ensure the default security group of every VPC
# restricts all traffic.
#
# Every VPC ships a "default" security group with one ingress rule
# (allow-all from self) and one egress rule (allow-all to
# 0.0.0.0/0). CIS expects both to be removed so workloads that
# accidentally land in the default SG carry no implicit traffic.
#
# The rule applies to security groups with group_name="default" —
# AWS uses that literal name for every VPC's default SG.

package cis_aws_1_5.cis_5_3

import rego.v1

sgs := [r | some r in input.resources; r.type == "aws.ec2.security_group"]

default_sgs := [r | some r in sgs; r.attrs.group_name == "default"]

applicable if {
	count(default_sgs) > 0
}

default applicable := false

violations contains v if {
	some r in default_sgs
	count(r.attrs.ingress_rules) > 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("default SG in VPC %q has %d ingress rule(s); CIS expects zero", [r.attrs.vpc_id, count(r.attrs.ingress_rules)]),
	}
}

violations contains v if {
	some r in default_sgs
	count(r.attrs.egress_rules) > 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("default SG in VPC %q has %d egress rule(s); CIS expects zero", [r.attrs.vpc_id, count(r.attrs.egress_rules)]),
	}
}

default status := "not_applicable"
default message := "No default security groups in scan input."
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

message := sprintf("All %d default security group(s) restrict all traffic.", [count(default_sgs)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d default-SG rule(s) found; CIS expects every default SG to be empty.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
