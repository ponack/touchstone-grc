# HIPAA Security Rule — 164.312(a)(2)(iv) Encryption and Decryption.
#
# Addressable implementation specification under the Access Control
# standard §164.312(a)(1). Covered entities must implement a
# mechanism to encrypt and decrypt ePHI when reasonable and
# appropriate.
#
# Touchstone evaluates encryption at rest across four storage
# surfaces (S3, EBS, RDS, EFS) — mirrors PCI 3.5.1.2. Any
# unencrypted resource on any surface is a finding.

package hipaa_security_rule.rule_164_312_a_2_iv

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

violations contains v if {
	some r in s3_buckets
	r.attrs.encryption.enabled != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("S3 bucket %q has no default encryption", [r.attrs.name]),
	}
}

violations contains v if {
	some r in ebs_regions
	r.attrs.enabled != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("region %q does not enable EBS encryption by default", [r.attrs.region]),
	}
}

violations contains v if {
	some r in rds_instances
	r.attrs.storage_encrypted != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("RDS instance %q is not encrypted at rest", [r.attrs.db_instance_identifier]),
	}
}

violations contains v if {
	some r in efs_filesystems
	r.attrs.encrypted != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("EFS file system %q is not encrypted at rest", [r.attrs.name]),
	}
}

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

message := "All ePHI storage surfaces are encrypted at rest." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d at-rest encryption finding(s) on ePHI storage surfaces.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
