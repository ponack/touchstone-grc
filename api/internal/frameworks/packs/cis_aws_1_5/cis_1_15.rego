# CIS AWS 1.5 — 1.15 Ensure IAM Users Receive Permissions Only Through
# Groups.
#
# Permissions should flow through group membership, not via policies
# attached or inlined directly on the user. A user with any direct
# (attached managed OR inline) policy is a finding even if its
# permissions happen to be safe — the rule is about the
# administrative pattern, not the effective access.

package cis_aws_1_5.cis_1_15

import rego.v1

users := [r | some r in input.resources; r.type == "aws.iam.user"]

applicable if {
	count(users) > 0
}

default applicable := false

violations contains v if {
	some r in users
	r.attrs.attached_policies_count > 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("IAM user %q has %d managed policy attached directly (use groups instead)", [r.attrs.user_name, r.attrs.attached_policies_count]),
	}
}

violations contains v if {
	some r in users
	r.attrs.inline_policies_count > 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("IAM user %q has %d inline policy attached directly (use groups instead)", [r.attrs.user_name, r.attrs.inline_policies_count]),
	}
}

default status := "not_applicable"
default message := "No IAM users in scan input."
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

message := "Every IAM user receives permissions only through groups." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d IAM user(s) carry direct policy attachments.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
