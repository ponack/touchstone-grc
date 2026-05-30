# CIS AWS 1.5 — 1.16 Ensure IAM policies that allow full "*:*"
# administrative privileges are not attached.
#
# Customer-managed policies that grant
# {"Effect":"Allow","Action":"*","Resource":"*"} and that are
# currently attached to any principal are findings. The scanner
# parses the policy document and pre-computes the is_admin flag, so
# the rego only needs to check the two booleans.
#
# AWS-managed policies (AdministratorAccess and friends) are out of
# scope per CIS — the rule targets *customer-defined* admin
# policies that should be retired.

package cis_aws_1_5.cis_1_16

import rego.v1

policies := [r | some r in input.resources; r.type == "aws.iam.customer_managed_policy"]

applicable if {
	count(policies) > 0
}

default applicable := false

violations contains v if {
	some r in policies
	r.attrs.is_admin == true
	r.attrs.attachment_count > 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("customer-managed policy %q grants Action=* / Resource=* and is attached to %d principal(s)", [r.attrs.policy_name, r.attrs.attachment_count]),
	}
}

default status := "not_applicable"
default message := "No customer-managed IAM policies in scan input."
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

message := "No customer-managed admin policy is attached to any principal." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d customer-managed admin policy attachment(s) — retire or restrict.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
