# SOC 2 2017 — CC6.7 Restricted data transmission / encryption.
#
# Rule (S3 surface): every bucket must have default encryption
# enabled. Algorithm AES256 (SSE-S3) or aws:kms / aws:kms:dsse are
# all acceptable — the failure mode this catches is "no encryption
# configured at all".
#
# TLS-only enforcement (denying non-HTTPS via bucket policy
# Condition: aws:SecureTransport=false) is a future extension that
# requires parsing the bucket policy document. Tracked separately.

package soc2_2017.cc6_7

import rego.v1

violations contains v if {
	some r in input.resources
	r.type == "aws.s3.bucket"
	r.attrs.encryption.enabled != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "default encryption is not configured",
	}
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

message := sprintf("%d S3 bucket(s) lack default encryption.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "All S3 buckets have default encryption enabled." if {
	applicable
	count(violations) == 0
}
