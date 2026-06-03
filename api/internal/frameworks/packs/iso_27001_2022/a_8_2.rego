# ISO/IEC 27001:2022 Annex A — A.8.2 Privileged access rights.
#
# Allocation and use of privileged access rights shall be restricted
# and managed.
#
# Touchstone's automated signal: AWS IAM users should not carry
# direct policy attachments — permissions must flow through group
# membership so reviews / modifications act on one named subject
# (the group) rather than scattered per-user policies.
#
# Same evidence as CIS 1.15 / PCI 7.2.5 / HIPAA 164.308(a)(4)(ii)(C).

package iso_27001_2022.a_8_2

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
		"reason":        sprintf("IAM user %q has %d managed policy attached directly", [r.attrs.user_name, r.attrs.attached_policies_count]),
	}
}

violations contains v if {
	some r in users
	r.attrs.inline_policies_count > 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("IAM user %q has %d inline policy attached directly", [r.attrs.user_name, r.attrs.inline_policies_count]),
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

message := "Every IAM user receives privileges through groups — review / modification scope is bounded." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d IAM user(s) carry direct policy attachments — privileged-access management scope is fragmented.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
