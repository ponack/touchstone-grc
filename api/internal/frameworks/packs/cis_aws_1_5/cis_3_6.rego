# CIS AWS 1.5 — 3.6 Ensure S3 bucket access logging is enabled on
# the CloudTrail S3 bucket.
#
# Server access logging on the trail's bucket gives a second
# evidence stream — operators can spot tampering, accidental
# deletions, or unauthorised reads of the audit logs themselves.
# Cross-reference: for every trail with a known bucket, the bucket's
# access_logging_enabled must be true.

package cis_aws_1_5.cis_3_6

import rego.v1

trails := [r | some r in input.resources; r.type == "aws.cloudtrail.trail"]
buckets := [r | some r in input.resources; r.type == "aws.s3.bucket"]

applicable if {
	count(trails) > 0
	count(buckets) > 0
}

default applicable := false

trail_bucket(t) := b if {
	some b in buckets
	b.attrs.name == t.attrs.s3_bucket_name
}

violations contains v if {
	some t in trails
	b := trail_bucket(t)
	b.attrs.access_logging_enabled != true
	v := {
		"resource_type": "aws.cloudtrail.trail",
		"resource_id":   t.id,
		"reason":        sprintf("CloudTrail bucket %q does not have server access logging enabled", [b.attrs.name]),
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

message := "Every observable CloudTrail S3 bucket has server access logging enabled." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d CloudTrail bucket(s) without access logging.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
