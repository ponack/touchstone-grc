# HIPAA Security Rule — 164.308(a)(3)(ii)(C) Termination Procedures.
#
# Required implementation specification under the Workforce
# Security standard. Covered entities must implement procedures
# for terminating access to ePHI when a workforce member's
# employment ends or when access is no longer authorized.
#
# Touchstone's automated signal: every Active IAM access key must
# have been created within 365 days. Stale long-lived keys are the
# canonical termination-gap finding — credentials that should have
# been disabled remain valid.
#
# Same evidence as SOC 2 CC6.3.

package hipaa_security_rule.rule_164_308_a_3_ii_c

import rego.v1

stale_age_seconds := 365 * 24 * 60 * 60

now_ns := time.now_ns()

users := [r | some r in input.resources; r.type == "aws.iam.user"]

applicable if {
	some r in users
	count(r.attrs.access_keys) > 0
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
		"reason":        sprintf("access key %v on IAM user %q is older than 365 days and still active", [k.access_key_id, r.attrs.user_name]),
	}
}

default status := "not_applicable"
default message := "No IAM access keys in scan input."
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

message := "All active IAM access keys are within the 365-day rotation window." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d stale long-lived credential(s) — termination procedures may be incomplete.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
