# CIS AWS 1.5 — 3.3 Ensure the S3 bucket used to store CloudTrail
# logs is not publicly accessible.
#
# Cross-reference: for every trail with a configured s3_bucket_name,
# locate the corresponding aws.s3.bucket in scan input and check
# (a) policy_status.is_public is false, AND (b) all four Public
# Access Block flags are enabled.
#
# Trails whose buckets aren't enumerated (cross-account log
# centralisation, for example) don't surface as findings — we only
# evaluate what we can observe.

package cis_aws_1_5.cis_3_3

import rego.v1

trails := [r | some r in input.resources; r.type == "aws.cloudtrail.trail"]
buckets := [r | some r in input.resources; r.type == "aws.s3.bucket"]

applicable if {
	count(trails) > 0
	count(buckets) > 0
}

default applicable := false

# trail_bucket(t) walks the resource set and returns the matching
# bucket for a trail. Failing the lookup means we can't evaluate.
trail_bucket(t) := b if {
	some b in buckets
	b.attrs.name == t.attrs.s3_bucket_name
}

bpa_fully_enabled(b) if {
	b.attrs.public_access_block.block_public_acls == true
	b.attrs.public_access_block.ignore_public_acls == true
	b.attrs.public_access_block.block_public_policy == true
	b.attrs.public_access_block.restrict_public_buckets == true
}

violations contains v if {
	some t in trails
	b := trail_bucket(t)
	b.attrs.policy_status.is_public == true
	v := {
		"resource_type": "aws.cloudtrail.trail",
		"resource_id":   t.id,
		"reason":        sprintf("CloudTrail bucket %q is marked public by its bucket policy", [b.attrs.name]),
	}
}

violations contains v if {
	some t in trails
	b := trail_bucket(t)
	not bpa_fully_enabled(b)
	v := {
		"resource_type": "aws.cloudtrail.trail",
		"resource_id":   t.id,
		"reason":        sprintf("CloudTrail bucket %q does not have Public Access Block fully enabled", [b.attrs.name]),
	}
}

default status := "not_applicable"
default message := "No CloudTrail trails + S3 buckets in scan input."
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

message := "Every observable CloudTrail S3 bucket is fully locked down." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d CloudTrail bucket finding(s).", [count(violations)]) if {
	applicable
	count(violations) > 0
}
