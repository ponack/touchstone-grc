# SOC 2 2017 — CC6.6 Network access controls.
#
# Rule (S3 surface): every bucket must be locked down from public
# access. Two failure modes:
#   - any of the four Public Access Block flags is disabled
#   - the bucket's policy status reports IsPublic == true
#
# CC6.6 also covers EC2 security groups + network ACLs. Those will
# extend this policy in a follow-up PR — until then this evaluates
# only S3 buckets present in scan input.

package soc2_2017.cc6_6

import rego.v1

# Bucket with any of the four BPA flags disabled.
bpa_violations contains v if {
	some r in input.resources
	r.type == "aws.s3.bucket"
	bpa := r.attrs.public_access_block
	some flag in ["block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"]
	bpa[flag] != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("Public Access Block flag %q is not enabled", [flag]),
	}
}

# Bucket whose policy makes it public.
policy_violations contains v if {
	some r in input.resources
	r.type == "aws.s3.bucket"
	r.attrs.policy_status.is_public == true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "bucket policy makes the bucket publicly accessible",
	}
}

# Combined finding set.
violations contains v if {
	some v in bpa_violations
}
violations contains v if {
	some v in policy_violations
}

applicable if {
	some r in input.resources
	r.type == "aws.s3.bucket"
}

default applicable := false

default status := "not_applicable"
default message := "No S3 buckets in scan input."
default failures := []

failures := [v | some v in violations]

status := "fail" if {
	applicable
	count(violations) > 0
}

status := "pass" if {
	applicable
	count(violations) == 0
}

message := sprintf("%d S3 bucket finding(s): public-access exposure.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "All S3 buckets enforce Block Public Access and have no public policy." if {
	applicable
	count(violations) == 0
}
