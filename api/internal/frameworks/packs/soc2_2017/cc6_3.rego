# SOC 2 2017 — CC6.3 User access revocation.
#
# Rule: active IAM access keys older than 365 days are flagged. Stale
# credentials are a primary CC6.3 finding — the longer a key lives
# unrotated, the higher the chance it has leaked or is held by a
# departed principal. 365 days is the conservative threshold; tighten
# in a custom pack if your control baseline is shorter.

package soc2_2017.cc6_3

import rego.v1

stale_age_seconds := 365 * 24 * 60 * 60 # one year

# Each active key older than stale_age_seconds produces one violation.
violations contains v if {
	some r in input.resources
	r.type == "aws.iam.user"
	some k in r.attrs.access_keys
	k.status == "Active"
	age_seconds := (time.now_ns() - time.parse_rfc3339_ns(k.create_date)) / 1000000000
	age_seconds > stale_age_seconds
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("access key %v is older than 365 days and still active", [k.access_key_id]),
	}
}

# Did we observe any IAM users with at least one access key?
applicable if {
	some r in input.resources
	r.type == "aws.iam.user"
	count(r.attrs.access_keys) > 0
}

default applicable := false

# ── Outputs ──────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No IAM users with access keys in scan input."
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

message := sprintf("%d active IAM access key(s) older than 365 days.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "All active IAM access keys are within the 365-day rotation window." if {
	applicable
	count(violations) == 0
}
