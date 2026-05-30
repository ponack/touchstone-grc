# CIS AWS 1.5 — 2.1.5 Ensure that S3 Buckets are configured with
# 'Block public access (bucket settings)'.
#
# Every bucket must have all four Public Access Block flags enabled:
# block_public_acls, ignore_public_acls, block_public_policy,
# restrict_public_buckets. CIS treats the configuration as binary —
# any flag off is a finding even when no actual public access exists
# today.

package cis_aws_1_5.cis_2_1_5

import rego.v1

required_flags := {"block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"}

buckets := [r | some r in input.resources; r.type == "aws.s3.bucket"]

applicable if {
	count(buckets) > 0
}

default applicable := false

violations contains v if {
	some r in buckets
	some flag in required_flags
	r.attrs.public_access_block[flag] != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("bucket %q has Public Access Block flag %q disabled", [r.attrs.name, flag]),
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

message := sprintf("All %d S3 bucket(s) have full Public Access Block enabled.", [count(buckets)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d Public Access Block finding(s) across S3 buckets.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
