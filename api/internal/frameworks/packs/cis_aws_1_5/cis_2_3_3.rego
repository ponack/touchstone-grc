# CIS AWS 1.5 — 2.3.3 Ensure that public access is not given to RDS
# Instance.
#
# publicly_accessible=true assigns a public IP to the instance.
# RDS databases should never be directly internet-facing — front
# them with a bastion / VPN / application tier instead. CIS fails
# any instance carrying the flag.

package cis_aws_1_5.cis_2_3_3

import rego.v1

instances := [r | some r in input.resources; r.type == "aws.rds.db_instance"]

applicable if {
	count(instances) > 0
}

default applicable := false

violations contains v if {
	some r in instances
	r.attrs.publicly_accessible == true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("RDS instance %q is marked publicly_accessible", [r.attrs.db_instance_identifier]),
	}
}

default status := "not_applicable"
default message := "No RDS instances in scan input."
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

message := sprintf("No RDS instance is publicly accessible (across %d instance(s)).", [count(instances)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d RDS instance(s) are publicly accessible.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
