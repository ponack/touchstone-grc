# SOC 2 2017 — CC6.6 Network access controls.
#
# Evaluates two AWS surfaces:
#
#   1. S3 buckets — Public Access Block + bucket-policy public flag.
#   2. EC2 security groups — ingress rules that expose sensitive
#      admin / database ports to the public internet.
#
# The control becomes "applicable" once either surface is present in
# the scan input, so adding more surfaces in follow-up PRs (NACLs,
# Network Firewall, ALB rules) is purely additive.

package soc2_2017.cc6_6

import rego.v1

# ── Sensitive ports ─────────────────────────────────────────────────
# Ports that should never be exposed to 0.0.0.0/0 in a healthy
# environment. Webservers (80/443) and high-port app traffic are
# intentionally omitted — those CAN legitimately be public.
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

# True if a rule's port range covers any sensitive port.
rule_hits_sensitive_port(rule) if {
	some p in sensitive_ports
	rule.from_port <= p
	rule.to_port >= p
}

# True if a rule's source includes the world.
rule_is_world_open(rule) if {
	some cidr in rule.ipv4_cidrs
	cidr == "0.0.0.0/0"
}
rule_is_world_open(rule) if {
	some cidr in rule.ipv6_cidrs
	cidr == "::/0"
}

# ── S3 violations ───────────────────────────────────────────────────

bpa_violations contains v if {
	some r in input.resources
	r.type == "aws.s3.bucket"
	bpa := r.attrs.public_access_block
	some flag in ["block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"]
	bpa[flag] != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("Public Access Block flag %q is not enabled", [flag]),
	}
}

policy_violations contains v if {
	some r in input.resources
	r.type == "aws.s3.bucket"
	r.attrs.policy_status.is_public == true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "bucket policy makes the bucket publicly accessible",
	}
}

# ── EC2 Security Group violations ───────────────────────────────────

# World-open ingress on a sensitive port.
sg_sensitive_port_violations contains v if {
	some r in input.resources
	r.type == "aws.ec2.security_group"
	some rule in r.attrs.ingress_rules
	rule_is_world_open(rule)
	rule_hits_sensitive_port(rule)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("ingress rule exposes ports %d-%d to the public internet, covers sensitive ports", [rule.from_port, rule.to_port]),
	}
}

# World-open all-protocols ingress is bad regardless of port range.
sg_all_protocols_violations contains v if {
	some r in input.resources
	r.type == "aws.ec2.security_group"
	some rule in r.attrs.ingress_rules
	rule_is_world_open(rule)
	rule.protocol == "-1"
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "ingress rule allows all protocols from the public internet",
	}
}

# ── Azure Storage Account violations ────────────────────────────────

# allow_blob_public_access == true means a container's owner can flip
# its access level to "Blob" or "Container" and serve to the world.
# CC6.6 wants that gate held shut at the account level.
azure_blob_public_violations contains v if {
	some r in input.resources
	r.type == "azure.storage.account"
	r.attrs.allow_blob_public_access == true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "storage account permits public blob access (allowBlobPublicAccess is true)",
	}
}

# Public network access controls the account-level firewall. "Disabled"
# is the strict choice. "Enabled" and "SecuredByPerimeter" are accepted
# for now (real-world buckets often legitimately face the internet);
# in a stricter v1 we may flag these too.

# ── Azure Network Security Group violations ─────────────────────────

# A source prefix that represents "anywhere on the public internet"
# in Azure's vocabulary. Azure uses "*" and the "Internet" service
# tag in addition to standard CIDR notation.
nsg_world_open(rule) if {
	some src in rule.source_prefixes
	src == "*"
}
nsg_world_open(rule) if {
	some src in rule.source_prefixes
	src == "Internet"
}
nsg_world_open(rule) if {
	some src in rule.source_prefixes
	src == "0.0.0.0/0"
}
nsg_world_open(rule) if {
	some src in rule.source_prefixes
	src == "::/0"
}

nsg_hits_sensitive_port(rule) if {
	some p in sensitive_ports
	rule.from_port <= p
	rule.to_port >= p
}

# Inbound rule (the scanner only emits Allow + Inbound rows) that's
# world-open and covers a sensitive admin/database port.
azure_nsg_sensitive_port_violations contains v if {
	some r in input.resources
	r.type == "azure.network.nsg"
	some rule in r.attrs.inbound_rules
	nsg_world_open(rule)
	nsg_hits_sensitive_port(rule)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("inbound rule %q exposes ports %d-%d to the public internet, covers sensitive ports", [rule.name, rule.from_port, rule.to_port]),
	}
}

# Inbound rule with protocol "*" (all protocols) from anywhere is
# always wrong.
azure_nsg_all_protocols_violations contains v if {
	some r in input.resources
	r.type == "azure.network.nsg"
	some rule in r.attrs.inbound_rules
	nsg_world_open(rule)
	rule.protocol == "*"
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("inbound rule %q allows all protocols from the public internet", [rule.name]),
	}
}

# ── Combined finding set ────────────────────────────────────────────

violations contains v if {
	some v in bpa_violations
}
violations contains v if {
	some v in policy_violations
}
violations contains v if {
	some v in sg_sensitive_port_violations
}
violations contains v if {
	some v in sg_all_protocols_violations
}
violations contains v if {
	some v in azure_blob_public_violations
}
violations contains v if {
	some v in azure_nsg_sensitive_port_violations
}
violations contains v if {
	some v in azure_nsg_all_protocols_violations
}

applicable if {
	some r in input.resources
	r.type == "aws.s3.bucket"
}
applicable if {
	some r in input.resources
	r.type == "aws.ec2.security_group"
}
applicable if {
	some r in input.resources
	r.type == "azure.storage.account"
}
applicable if {
	some r in input.resources
	r.type == "azure.network.nsg"
}

default applicable := false

default status := "not_applicable"
default message := "No network-relevant resources in scan input."
default failures := []

failures := [v | some v in violations]

status := "fail" if {
	applicable
	count(violations) > 0
}

status := "pass" if {
	applicable
	count(violations) == 0
}

message := sprintf("%d network access finding(s) across AWS + Azure surfaces.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "All network resources restrict public access." if {
	applicable
	count(violations) == 0
}
