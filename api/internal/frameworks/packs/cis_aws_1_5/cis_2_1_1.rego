# CIS AWS 1.5 — 2.1.1 Ensure all S3 buckets employ encryption-at-rest.
#
# Every aws.s3.bucket must have default encryption configured
# (SSE-S3 / SSE-KMS / DSSE-KMS — anything but "no encryption"). Same
# evidence as SOC 2 CC6.7's S3 surface, framed per-bucket as CIS
# expects.

package cis_aws_1_5.cis_2_1_1

import rego.v1

buckets := [r | some r in input.resources; r.type == "aws.s3.bucket"]

applicable if {
	count(buckets) > 0
}

default applicable := false

violations contains v if {
	some r in buckets
	r.attrs.encryption.enabled != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("bucket %q has no default encryption configured", [r.attrs.name]),
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

message := sprintf("All %d S3 bucket(s) have default encryption enabled.", [count(buckets)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d S3 bucket(s) lack default encryption.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
