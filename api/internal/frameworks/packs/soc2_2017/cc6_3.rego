# SOC 2 2017 — CC6.3 User access revocation / credential rotation.
#
# Evaluates three surfaces:
#
#   AWS IAM           Active access keys older than 365 days.
#   Azure AD apps     Application registration password credentials
#                     (client secrets) or key credentials (certs)
#                     that were issued more than 365 days ago AND
#                     remain currently valid (end_date > now).
#   GCP IAM service   User-managed service account keys older than
#                     365 days. System-managed keys (Google-rotated)
#                     are filtered out at the scanner.
#
# 365 days is the conservative rotation baseline; tighten in a custom
# pack if your control framework requires shorter rotation. The
# behaviour is symmetric across clouds — each currently-active
# stale credential is one violation row.

package soc2_2017.cc6_3

import rego.v1

stale_age_seconds := 365 * 24 * 60 * 60 # one year

now_ns := time.now_ns()

# ── AWS IAM access keys ─────────────────────────────────────────────

violations contains v if {
	some r in input.resources
	r.type == "aws.iam.user"
	some k in r.attrs.access_keys
	k.status == "Active"
	age_seconds := (now_ns - time.parse_rfc3339_ns(k.create_date)) / 1000000000
	age_seconds > stale_age_seconds
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("access key %v is older than 365 days and still active", [k.access_key_id]),
	}
}

# ── Azure AD application credentials ────────────────────────────────

azure_credential_stale(c) if {
	c.start_date != ""
	c.end_date != ""
	start_ns := time.parse_rfc3339_ns(c.start_date)
	end_ns := time.parse_rfc3339_ns(c.end_date)
	now_ns < end_ns # not yet expired
	(now_ns - start_ns) / 1000000000 > stale_age_seconds
}

violations contains v if {
	some r in input.resources
	r.type == "azure.ad.application"
	some c in r.attrs.password_credentials
	azure_credential_stale(c)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("client secret %v has been valid for more than 365 days", [c.display_name]),
	}
}

violations contains v if {
	some r in input.resources
	r.type == "azure.ad.application"
	some c in r.attrs.key_credentials
	azure_credential_stale(c)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("certificate %v has been valid for more than 365 days", [c.display_name]),
	}
}

# ── GCP IAM service account keys ────────────────────────────────────

violations contains v if {
	some r in input.resources
	r.type == "gcp.iam.service_account"
	some k in r.attrs.keys
	k.key_type == "USER_MANAGED"
	age_seconds := (now_ns - time.parse_rfc3339_ns(k.valid_after_time)) / 1000000000
	age_seconds > stale_age_seconds
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("user-managed key %v on service account %v is older than 365 days", [k.id, r.attrs.email]),
	}
}

# ── Applicability ───────────────────────────────────────────────────

applicable if {
	some r in input.resources
	r.type == "aws.iam.user"
	count(r.attrs.access_keys) > 0
}
applicable if {
	some r in input.resources
	r.type == "azure.ad.application"
	count(r.attrs.password_credentials) > 0
}
applicable if {
	some r in input.resources
	r.type == "azure.ad.application"
	count(r.attrs.key_credentials) > 0
}
applicable if {
	some r in input.resources
	r.type == "gcp.iam.service_account"
	count(r.attrs.keys) > 0
}

default applicable := false

# ── Outputs ─────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No long-lived credentials in scan input."
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

message := sprintf("%d credential rotation finding(s) across configured clouds.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "All long-lived credentials are within the 365-day rotation window." if {
	applicable
	count(violations) == 0
}
