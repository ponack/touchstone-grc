# ISO/IEC 27001:2022 Annex A — A.8.20 Networks security.
#
# Networks and network devices shall be secured, managed and
# controlled to protect information in systems and applications.
#
# Touchstone evaluates two AWS surfaces:
#
#   AWS S3                  — every bucket must have all four
#                              Public Access Block flags enabled,
#                              and the bucket policy must not make
#                              the bucket public.
#   AWS EC2 security groups — no world-open (0.0.0.0/0 or ::/0)
#                              ingress on sensitive admin / database
#                              ports, and no world-open all-
#                              protocols ingress.
#
# Same evidence as SOC 2 CC6.6 / CIS 5.2 / CIS 2.1.5.

package iso_27001_2022.a_8_20

import rego.v1

sensitive_ports := {
	22, # SSH
	3389, # RDP
	3306, # MySQL / MariaDB
	5432, # PostgreSQL
	1433, # MS SQL
	1521, # Oracle
	27017, # MongoDB
	6379, # Redis
	9200, # Elasticsearch
	11211, # Memcached
}

buckets := [r | some r in input.resources; r.type == "aws.s3.bucket"]
security_groups := [r | some r in input.resources; r.type == "aws.ec2.security_group"]

applicable if {
	count(buckets) > 0
}
applicable if {
	count(security_groups) > 0
}

default applicable := false

rule_hits_sensitive_port(rule) if {
	some p in sensitive_ports
	rule.from_port <= p
	rule.to_port >= p
}

rule_is_world_open(rule) if {
	some cidr in rule.ipv4_cidrs
	cidr == "0.0.0.0/0"
}
rule_is_world_open(rule) if {
	some cidr in rule.ipv6_cidrs
	cidr == "::/0"
}

violations contains v if {
	some r in buckets
	bpa := r.attrs.public_access_block
	some flag in ["block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"]
	bpa[flag] != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("S3 bucket %q has Public Access Block flag %q disabled", [r.attrs.name, flag]),
	}
}

violations contains v if {
	some r in buckets
	r.attrs.policy_status.is_public == true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("S3 bucket %q has a policy that makes it publicly accessible", [r.attrs.name]),
	}
}

violations contains v if {
	some r in security_groups
	some rule in r.attrs.ingress_rules
	rule_is_world_open(rule)
	rule_hits_sensitive_port(rule)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("ingress rule exposes ports %d-%d to the public internet, covers sensitive ports", [rule.from_port, rule.to_port]),
	}
}

violations contains v if {
	some r in security_groups
	some rule in r.attrs.ingress_rules
	rule_is_world_open(rule)
	rule.protocol == "-1"
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "ingress rule allows all protocols from the public internet",
	}
}

default status := "not_applicable"
default message := "No network-relevant resources in scan input."
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

message := "All AWS network surfaces restrict public access." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d network-security finding(s) on AWS S3 / EC2 surfaces.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
