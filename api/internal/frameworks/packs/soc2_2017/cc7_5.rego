# SOC 2 2017 — CC7.5 Recovery procedures.
#
# Evaluates relational-DB recovery posture across three surfaces:
#
#   AWS RDS              backup_retention_period >= 7 days
#                        AND deletion_protection == true
#   Azure SQL DB         backup_retention_period (short-term) >= 7 days.
#                        Azure SQL has no per-DB deletion_protection
#                        toggle equivalent — soft-delete is handled
#                        at the subscription / resource-lock level,
#                        which we will check in a follow-up.
#   GCP Cloud SQL        backup_enabled == true
#                        AND backup_retention_days >= 7
#                        AND deletion_protection == true.
#                        Point-in-time recovery (PITR) is recorded
#                        for evidence but not gated on — operators
#                        sometimes legitimately turn it off for
#                        replica-heavy topologies.
#
# Applicability fires only when at least one supported DB exists in
# scan input. Accounts with no relational databases (DynamoDB-only,
# S3-only, Cosmos-only) yield not_applicable here — recovery for
# those services lives in their own controls.

package soc2_2017.cc7_5

import rego.v1

min_backup_days := 7

# ── AWS RDS ─────────────────────────────────────────────────────────

rds_dbs := [r | some r in input.resources; r.type == "aws.rds.db_instance"]

violations contains v if {
	some db in rds_dbs
	db.attrs.backup_retention_period < min_backup_days
	v := {
		"resource_type": db.type,
		"resource_id":   db.id,
		"reason":        sprintf("backup_retention_period is %d day(s); recovery baseline is %d", [db.attrs.backup_retention_period, min_backup_days]),
	}
}

violations contains v if {
	some db in rds_dbs
	db.attrs.deletion_protection != true
	v := {
		"resource_type": db.type,
		"resource_id":   db.id,
		"reason":        "deletion_protection is not enabled — an accidental DeleteDBInstance can lose all data",
	}
}

# ── Azure SQL ───────────────────────────────────────────────────────

azure_dbs := [r | some r in input.resources; r.type == "azure.sql.database"]

violations contains v if {
	some db in azure_dbs
	db.attrs.backup_retention_period < min_backup_days
	v := {
		"resource_type": db.type,
		"resource_id":   db.id,
		"reason":        sprintf("short-term backup retention is %d day(s); recovery baseline is %d", [db.attrs.backup_retention_period, min_backup_days]),
	}
}

# ── GCP Cloud SQL ───────────────────────────────────────────────────

gcp_dbs := [r | some r in input.resources; r.type == "gcp.sql.instance"]

violations contains v if {
	some db in gcp_dbs
	db.attrs.backup_enabled != true
	v := {
		"resource_type": db.type,
		"resource_id":   db.id,
		"reason":        "automated backups are disabled — no recovery point available",
	}
}

violations contains v if {
	some db in gcp_dbs
	db.attrs.backup_enabled == true
	db.attrs.backup_retention_days < min_backup_days
	v := {
		"resource_type": db.type,
		"resource_id":   db.id,
		"reason":        sprintf("backup_retention_days is %d; recovery baseline is %d", [db.attrs.backup_retention_days, min_backup_days]),
	}
}

violations contains v if {
	some db in gcp_dbs
	db.attrs.deletion_protection != true
	v := {
		"resource_type": db.type,
		"resource_id":   db.id,
		"reason":        "deletion_protection is not enabled — an accidental DeleteInstance can lose all data",
	}
}

# ── Applicability + outputs ─────────────────────────────────────────

applicable if count(rds_dbs) > 0
applicable if count(azure_dbs) > 0
applicable if count(gcp_dbs) > 0

default applicable := false

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

message := sprintf("All %d database(s) meet recovery baselines: backups >= %d days.", [count(rds_dbs) + count(azure_dbs) + count(gcp_dbs), min_backup_days]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d recovery finding(s) across configured databases.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
