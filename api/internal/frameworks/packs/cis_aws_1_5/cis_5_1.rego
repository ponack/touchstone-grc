# CIS AWS 1.5 — 5.1 Ensure no Network ACLs allow ingress from
# 0.0.0.0/0 to remote server administration ports.
#
# Remote server administration ports per CIS = 22 (SSH) and 3389
# (RDP). Any NACL ingress entry that ALLOWs traffic from 0.0.0.0/0
# (or ::/0) and whose port range covers 22 or 3389 is a finding.
# DENY entries don't trigger — they restrict, not enable.

package cis_aws_1_5.cis_5_1

import rego.v1

admin_ports := {22, 3389}

nacls := [r | some r in input.resources; r.type == "aws.ec2.network_acl"]

applicable if {
	count(nacls) > 0
}

default applicable := false

world_open(rule) if {
	rule.cidr_block == "0.0.0.0/0"
}
world_open(rule) if {
	rule.ipv6_cidr_block == "::/0"
}

covers_admin_port(rule) if {
	some p in admin_ports
	rule.from_port <= p
	rule.to_port >= p
}

violations contains v if {
	some r in nacls
	some rule in r.attrs.ingress_rules
	rule.rule_action == "allow"
	world_open(rule)
	covers_admin_port(rule)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("NACL %q allows world-open ingress on admin port range %d-%d", [r.attrs.network_acl_id, rule.from_port, rule.to_port]),
	}
}

default status := "not_applicable"
default message := "No Network ACLs in scan input."
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

message := sprintf("No NACL allows world-open admin-port ingress (across %d NACL(s)).", [count(nacls)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d NACL ingress finding(s) for admin ports.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
