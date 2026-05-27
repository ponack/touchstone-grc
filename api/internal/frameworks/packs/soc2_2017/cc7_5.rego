# SOC 2 2017 — CC7.5 Recovery procedures.
#
# Rule (RDS surface): every RDS DB instance must have:
#   - automated backups enabled (backup_retention_period >= 7)
#   - deletion protection enabled (deletion_protection == true)
#
# Together those mean "if the DB is corrupted, dropped, or
# accidentally deleted, the data is recoverable from at least a
# week of point-in-time backups". This is the auditor-friendly
# proxy for 'we have a recovery procedure' on a relational DB.
#
# Future extensions: S3 versioning + cross-region replication,
# DynamoDB point-in-time recovery, EBS snapshot policies, AWS
# Backup vault coverage.
#
# Applicability: only fires when RDS instances are in scan input.
# An account with no RDS (e.g. DynamoDB-only architecture) yields
# not_applicable here — the recovery story for those services is
# evaluated by their own controls when they ship.

package soc2_2017.cc7_5

import rego.v1

min_backup_days := 7

dbs := [r | some r in input.resources; r.type == "aws.rds.db_instance"]

applicable if {
	count(dbs) > 0
}

default applicable := false

# ── Violations ──────────────────────────────────────────────────────

violations contains v if {
	applicable
	some db in dbs
	db.attrs.backup_retention_period < min_backup_days
	v := {
		"resource_type": db.type,
		"resource_id":   db.id,
		"reason":        sprintf("backup_retention_period is %d day(s); recovery baseline is %d", [db.attrs.backup_retention_period, min_backup_days]),
	}
}

violations contains v if {
	applicable
	some db in dbs
	db.attrs.deletion_protection != true
	v := {
		"resource_type": db.type,
		"resource_id":   db.id,
		"reason":        "deletion_protection is not enabled — an accidental DeleteDBInstance can lose all data",
	}
}

# ── Outputs ─────────────────────────────────────────────────────────

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

message := sprintf("All %d RDS instance(s) have recovery configured: backups >= %d days + deletion protection.", [count(dbs), min_backup_days]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d RDS instance recovery finding(s) — backup retention or deletion protection gap.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
