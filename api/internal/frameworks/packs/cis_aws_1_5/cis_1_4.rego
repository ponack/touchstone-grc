# CIS AWS 1.5 — 1.4 Ensure no 'root' user account access key exists.
#
# The root user should never have a long-lived programmatic
# credential. AWS sets the AccountAccessKeysPresent summary flag to
# the count of root access keys; any non-zero count is a fail.
#
# Applicability fires whenever an aws.iam.account_summary resource
# is present in scan input. Accounts that didn't scan AWS yield
# not_applicable.

package cis_aws_1_5.cis_1_4

import rego.v1

summaries := [r | some r in input.resources; r.type == "aws.iam.account_summary"]

applicable if {
	count(summaries) > 0
}

default applicable := false

violations contains v if {
	some r in summaries
	r.attrs.root_access_keys_present == true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "the root user has at least one access key configured",
	}
}

default status := "not_applicable"
default message := "No AWS account summary in scan input."
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

message := "Root user has no access keys." if {
	applicable
	count(violations) == 0
}

message := "Root user has at least one access key — remove it." if {
	applicable
	count(violations) > 0
}
