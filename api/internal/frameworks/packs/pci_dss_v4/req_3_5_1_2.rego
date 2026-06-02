# PCI DSS v4.0 — 3.5.1.2 Disk- or partition-level encryption for
# stored account data.
#
# Stored account data must be rendered unreadable through
# disk- / partition-level encryption. Touchstone evaluates four
# storage surfaces in parallel, each emitting one violation per
# unencrypted resource:
#
#   AWS S3              — default encryption configured
#   AWS EBS             — encryption-by-default enabled per region
#   AWS RDS             — storage_encrypted=true per instance
#   AWS EFS             — encrypted=true per file system
#
# A single unencrypted resource on any surface fails the control.

package pci_dss_v4.req_3_5_1_2

import rego.v1

s3_buckets := [r | some r in input.resources; r.type == "aws.s3.bucket"]
ebs_regions := [r | some r in input.resources; r.type == "aws.ec2.ebs_encryption_region"]
rds_instances := [r | some r in input.resources; r.type == "aws.rds.db_instance"]
efs_filesystems := [r | some r in input.resources; r.type == "aws.efs.file_system"]

applicable if {
	count(s3_buckets) > 0
}
applicable if {
	count(ebs_regions) > 0
}
applicable if {
	count(rds_instances) > 0
}
applicable if {
	count(efs_filesystems) > 0
}

default applicable := false

# ── S3 ─────────────────────────────────────────────────────────────

violations contains v if {
	some r in s3_buckets
	r.attrs.encryption.enabled != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("S3 bucket %q has no default encryption", [r.attrs.name]),
	}
}

# ── EBS (per region) ───────────────────────────────────────────────

violations contains v if {
	some r in ebs_regions
	r.attrs.enabled != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("region %q does not enable EBS encryption by default", [r.attrs.region]),
	}
}

# ── RDS ────────────────────────────────────────────────────────────

violations contains v if {
	some r in rds_instances
	r.attrs.storage_encrypted != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("RDS instance %q is not encrypted at rest", [r.attrs.db_instance_identifier]),
	}
}

# ── EFS ────────────────────────────────────────────────────────────

violations contains v if {
	some r in efs_filesystems
	r.attrs.encrypted != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("EFS file system %q is not encrypted at rest", [r.attrs.name]),
	}
}

# ── Outputs ────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No storage resources in scan input."
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

message := "All stored-data surfaces are encrypted at rest." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d at-rest encryption finding(s) across S3 / EBS / RDS / EFS.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
