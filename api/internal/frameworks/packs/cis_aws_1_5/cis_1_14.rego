# CIS AWS 1.5 — 1.14 Ensure access keys are rotated every 90 days or
# less.
#
# Active access keys older than 90 days are violations. Inactive
# keys do not count — they're already out of circulation, though
# CIS 1.13 / SOC 2 CC6.3 may still flag them for other reasons.
#
# This rule overlaps SOC 2 CC6.3 (365-day threshold) on the same
# evidence — different rotation baselines, same access-key data.

package cis_aws_1_5.cis_1_14

import rego.v1

stale_age_seconds := 90 * 24 * 60 * 60

now_ns := time.now_ns()

users := [r | some r in input.resources; r.type == "aws.iam.user"]

applicable if {
	some r in users
	some k in r.attrs.access_keys
	k.status == "Active"
}

default applicable := false

violations contains v if {
	some r in users
	some k in r.attrs.access_keys
	k.status == "Active"
	age_seconds := (now_ns - time.parse_rfc3339_ns(k.create_date)) / 1000000000
	age_seconds > stale_age_seconds
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("access key %v for IAM user %q is older than 90 days and still active", [k.access_key_id, r.attrs.user_name]),
	}
}

default status := "not_applicable"
default message := "No active IAM access keys in scan input."
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

message := "Every active access key has been rotated within 90 days." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d active access key(s) older than 90 days.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
