# CIS AWS 1.5 — 2.3.1 Ensure that encryption-at-rest is enabled for
# RDS Instances.
#
# storage_encrypted is a one-shot flag at instance creation; it
# cannot be enabled in place. CIS scopes this to every RDS instance
# Touchstone enumerates — including replicas and serverless.

package cis_aws_1_5.cis_2_3_1

import rego.v1

instances := [r | some r in input.resources; r.type == "aws.rds.db_instance"]

applicable if {
	count(instances) > 0
}

default applicable := false

violations contains v if {
	some r in instances
	r.attrs.storage_encrypted != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("RDS instance %q does not have storage_encrypted=true", [r.attrs.db_instance_identifier]),
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

message := sprintf("All %d RDS instance(s) have encryption-at-rest enabled.", [count(instances)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d RDS instance(s) without encryption-at-rest.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
