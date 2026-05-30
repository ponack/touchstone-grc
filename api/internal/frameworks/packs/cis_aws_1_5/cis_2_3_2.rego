# CIS AWS 1.5 — 2.3.2 Ensure Auto Minor Version Upgrade feature is
# Enabled for RDS Instances.
#
# Minor versions ship security patches; auto-upgrade keeps instances
# on a supported, patched baseline without scheduled maintenance
# windows missing the window. CIS treats the flag as binary.

package cis_aws_1_5.cis_2_3_2

import rego.v1

instances := [r | some r in input.resources; r.type == "aws.rds.db_instance"]

applicable if {
	count(instances) > 0
}

default applicable := false

violations contains v if {
	some r in instances
	r.attrs.auto_minor_version_upgrade != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("RDS instance %q has auto_minor_version_upgrade disabled", [r.attrs.db_instance_identifier]),
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

message := sprintf("All %d RDS instance(s) carry auto minor version upgrade.", [count(instances)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d RDS instance(s) without auto minor version upgrade.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
