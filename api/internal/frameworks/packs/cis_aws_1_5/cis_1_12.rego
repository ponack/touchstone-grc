# CIS AWS 1.5 — 1.12 Ensure credentials unused for 45 days or greater
# are disabled.
#
# Covers two credential types:
#
#   Console password — if a user has a login profile and the
#     password was either never used after creation, or last used
#     more than 45 days ago.
#   Access keys      — for every Active access key, if it was either
#     never used after creation, or last used more than 45 days ago.
#
# The 45-day clock starts at creation: a freshly-created credential
# isn't a violation just because it hasn't been used yet. After 45
# days the auditor expects either evidence of use or disablement.

package cis_aws_1_5.cis_1_12

import rego.v1

stale_age_seconds := 45 * 24 * 60 * 60

now_ns := time.now_ns()

users := [r | some r in input.resources; r.type == "aws.iam.user"]

# Has the credential aged past the grace window since creation?
created_long_enough(create_date) if {
	age_seconds := (now_ns - time.parse_rfc3339_ns(create_date)) / 1000000000
	age_seconds > stale_age_seconds
}

# Has the credential been used inside the freshness window?
used_recently(last_used_date) if {
	last_used_date != null
	age_seconds := (now_ns - time.parse_rfc3339_ns(last_used_date)) / 1000000000
	age_seconds <= stale_age_seconds
}

# ── Applicability ───────────────────────────────────────────────────
# The rule is applicable as soon as any IAM user that *could* host a
# stale credential is present in scope — i.e. a console user past
# the grace window, or any active access key past the grace window.

applicable if {
	some r in users
	r.attrs.has_console == true
	created_long_enough(r.attrs.create_date)
}

applicable if {
	some r in users
	some k in r.attrs.access_keys
	k.status == "Active"
	created_long_enough(k.create_date)
}

default applicable := false

# ── Console password violations ─────────────────────────────────────

violations contains v if {
	some r in users
	r.attrs.has_console == true
	created_long_enough(r.attrs.create_date)
	not used_recently(r.attrs.password_last_used)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("console password for IAM user %q has not been used in 45+ days", [r.attrs.user_name]),
	}
}

# ── Access key violations ───────────────────────────────────────────

violations contains v if {
	some r in users
	some k in r.attrs.access_keys
	k.status == "Active"
	created_long_enough(k.create_date)
	not used_recently(k.last_used_date)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("access key %v for IAM user %q has not been used in 45+ days", [k.access_key_id, r.attrs.user_name]),
	}
}

# ── Outputs ─────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No IAM credentials past the 45-day grace window in scan input."
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

message := "Every IAM credential beyond the 45-day grace window has been used inside the freshness window." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d stale IAM credential(s) — disable or rotate.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
