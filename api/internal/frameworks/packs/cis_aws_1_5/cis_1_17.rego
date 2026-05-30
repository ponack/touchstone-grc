# CIS AWS 1.5 — 1.17 Ensure a support role has been created to manage
# incidents with AWS Support.
#
# At least one IAM principal (user, group, or role) must hold the
# AWS managed AWSSupportAccess policy so support tickets can be
# opened without escalating root.
#
# Applicability fires whenever the scanner emitted the
# aws.iam.support_access_summary resource — i.e. the AWS scan
# completed enough to enumerate policy attachments.

package cis_aws_1_5.cis_1_17

import rego.v1

summaries := [r | some r in input.resources; r.type == "aws.iam.support_access_summary"]

applicable if {
	count(summaries) > 0
}

default applicable := false

violations contains v if {
	some r in summaries
	r.attrs.total_attachment_count == 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "no IAM principal holds the AWSSupportAccess policy — create a support role",
	}
}

default status := "not_applicable"
default message := "No AWS scan input."
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

message := "At least one IAM principal can open AWS Support cases." if {
	applicable
	count(violations) == 0
}

message := "No IAM principal carries AWSSupportAccess — file support tickets becomes a root-only operation." if {
	applicable
	count(violations) > 0
}
