# PCI DSS v4.0 — 1.3.2 Restrict inbound traffic from untrusted
# networks to the CDE.
#
# Remote administration ports must not accept traffic from the
# public internet. PCI explicitly calls out SSH (22) and RDP (3389)
# as examples; Touchstone evaluates the same pair against AWS
# security groups (mirroring CIS 5.2). Findings flag world-open
# ingress on either port.

package pci_dss_v4.req_1_3_2

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

message := sprintf("No security group permits world-open admin-port ingress (across %d SG(s)).", [count(sgs)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d security group(s) accept inbound admin traffic from the public internet.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
