# CIS AWS 1.5 — 2.1.3 Ensure MFA Delete is enabled on S3 buckets.
#
# MFA Delete requires a one-time MFA token on every DeleteObject /
# DeleteBucket request once enabled, defeating credential-only
# deletion of versioned objects. Versioning is a hard prerequisite —
# MFA Delete cannot be enabled without it.

package cis_aws_1_5.cis_2_1_3

import rego.v1

buckets := [r | some r in input.resources; r.type == "aws.s3.bucket"]

applicable if {
	count(buckets) > 0
}

default applicable := false

violations contains v if {
	some r in buckets
	r.attrs.versioning_mfa_delete != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("bucket %q does not have MFA Delete enabled", [r.attrs.name]),
	}
}

default status := "not_applicable"
default message := "No S3 buckets in scan input."
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

message := sprintf("All %d S3 bucket(s) require MFA on object deletion.", [count(buckets)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d S3 bucket(s) without MFA Delete.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
