# CIS AWS 1.5 — 1.13 Ensure there is only one active access key
# available for any single IAM user.
#
# Two active keys per user means rotation became "create a second
# key" rather than "rotate the existing one". CIS treats this as a
# credential-hygiene gap: stale keys linger after the rotation
# nominally completed. Inactive keys do not count.

package cis_aws_1_5.cis_1_13

import rego.v1

users := [r | some r in input.resources; r.type == "aws.iam.user"]

# Per-user count of currently-Active access keys.
active_key_count(r) := n if {
	n := count([k | some k in r.attrs.access_keys; k.status == "Active"])
}

applicable if {
	some r in users
	count(r.attrs.access_keys) > 0
}

default applicable := false

violations contains v if {
	some r in users
	active_key_count(r) > 1
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("IAM user %q has %d active access keys (CIS expects at most one)", [r.attrs.user_name, active_key_count(r)]),
	}
}

default status := "not_applicable"
default message := "No IAM users with access keys in scan input."
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

message := "Every IAM user has at most one active access key." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d IAM user(s) carry more than one active access key.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
