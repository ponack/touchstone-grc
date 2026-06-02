# HIPAA Security Rule — 164.308(a)(7)(ii)(A) Data Backup Plan.
#
# Required implementation specification under the Contingency Plan
# standard. Covered entities must establish and implement procedures
# to create and maintain retrievable exact copies of ePHI.
#
# Touchstone's automated signal: every RDS instance must have
# automated backups configured with a retention period of at least
# 7 days. Mirrors SOC 2 CC7.5 — same 7-day baseline.

package hipaa_security_rule.rule_164_308_a_7_ii_a

import rego.v1

min_backup_days := 7

rds_dbs := [r | some r in input.resources; r.type == "aws.rds.db_instance"]

applicable if {
	count(rds_dbs) > 0
}

default applicable := false

violations contains v if {
	some db in rds_dbs
	db.attrs.backup_retention_period < min_backup_days
	v := {
		"resource_type": db.type,
		"resource_id":   db.id,
		"reason":        sprintf("RDS instance %q has backup_retention_period=%d days (minimum %d)", [db.attrs.db_instance_identifier, db.attrs.backup_retention_period, min_backup_days]),
	}
}

default status := "not_applicable"
default message := "No relational database resources in scan input."
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

message := sprintf("All RDS instance(s) carry at least %d days of automated backups.", [min_backup_days]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d RDS instance(s) below the %d-day backup retention baseline.", [count(violations), min_backup_days]) if {
	applicable
	count(violations) > 0
}
