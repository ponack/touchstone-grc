# CIS AWS 1.5 — 1.19 Ensure that all the expired SSL/TLS certificates
# stored in AWS IAM are removed.
#
# Any aws.iam.server_certificate whose expiration has already passed
# is a finding. Certs with a missing expiration field (legacy
# uploads) pass — IAM no longer accepts uploads without one, but
# defensive against missing data.
#
# This rule does not flag certs that will expire soon — only ones
# that already have. A separate hygiene rule (expires-within-30-days)
# may follow as a stricter v1.

package cis_aws_1_5.cis_1_19

import rego.v1

now_ns := time.now_ns()

certs := [r | some r in input.resources; r.type == "aws.iam.server_certificate"]

applicable if {
	count(certs) > 0
}

default applicable := false

violations contains v if {
	some r in certs
	r.attrs.expiration != null
	exp_ns := time.parse_rfc3339_ns(r.attrs.expiration)
	exp_ns < now_ns
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("server certificate %q expired at %v", [r.attrs.server_certificate_name, r.attrs.expiration]),
	}
}

default status := "not_applicable"
default message := "No IAM server certificates in scan input."
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

message := sprintf("All %d IAM server certificate(s) are within their validity window.", [count(certs)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d expired IAM server certificate(s) — remove them.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
