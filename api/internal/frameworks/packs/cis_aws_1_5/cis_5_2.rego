# CIS AWS 1.5 — 5.2 Ensure no security groups allow ingress from
# 0.0.0.0/0 to remote server administration ports.
#
# Same admin-port set as CIS 5.1: 22 (SSH) and 3389 (RDP). Same
# evidence as SOC 2 CC6.6 but CIS narrows to the two admin ports
# instead of the broader sensitive-port set.

package cis_aws_1_5.cis_5_2

import rego.v1

admin_ports := {22, 3389}

sgs := [r | some r in input.resources; r.type == "aws.ec2.security_group"]

applicable if {
	count(sgs) > 0
}

default applicable := false

sg_world_open(rule) if {
	some cidr in rule.ipv4_cidrs
	cidr == "0.0.0.0/0"
}
sg_world_open(rule) if {
	some cidr in rule.ipv6_cidrs
	cidr == "::/0"
}

sg_covers_admin_port(rule) if {
	some p in admin_ports
	rule.from_port <= p
	rule.to_port >= p
}

violations contains v if {
	some r in sgs
	some rule in r.attrs.ingress_rules
	sg_world_open(rule)
	sg_covers_admin_port(rule)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("security group %q allows world-open ingress on admin port range %d-%d", [r.attrs.group_id, rule.from_port, rule.to_port]),
	}
}

default status := "not_applicable"
default message := "No security groups in scan input."
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

message := sprintf("No security group allows world-open admin-port ingress (across %d SG(s)).", [count(sgs)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d security group ingress finding(s) for admin ports.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
