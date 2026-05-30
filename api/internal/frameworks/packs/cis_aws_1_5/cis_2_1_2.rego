# CIS AWS 1.5 — 2.1.2 Ensure S3 Bucket Policy is set to deny HTTP
# requests.
#
# Every bucket must carry a Deny statement that fires when
# aws:SecureTransport is false. The scanner pre-computes the boolean
# enforces_https_only so the rego only checks one flag.

package cis_aws_1_5.cis_2_1_2

import rego.v1

buckets := [r | some r in input.resources; r.type == "aws.s3.bucket"]

applicable if {
	count(buckets) > 0
}

default applicable := false

violations contains v if {
	some r in buckets
	r.attrs.enforces_https_only != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("bucket %q policy does not deny aws:SecureTransport=false", [r.attrs.name]),
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

message := sprintf("All %d S3 bucket(s) deny non-HTTPS requests in policy.", [count(buckets)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d S3 bucket(s) accept HTTP requests.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
