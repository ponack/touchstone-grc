# HIPAA Security Rule — 164.308(a)(4)(ii)(C) Access Establishment
# and Modification.
#
# Required implementation specification under the Information
# Access Management standard. Covered entities must implement
# policies and procedures that establish, document, review, and
# modify a user's right of access to ePHI.
#
# Touchstone's automated signal: AWS IAM users should not carry
# direct policy attachments — permissions must flow through group
# membership so reviews / modifications act on one named subject
# (the group) rather than scattered per-user policies.
#
# Same evidence as CIS 1.15 / PCI 7.2.5.

package hipaa_security_rule.rule_164_308_a_4_ii_c

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

message := "Every IAM user receives ePHI access through groups — reviews / modifications can act on the group." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d IAM user(s) carry direct policy attachments — review / modification scope is fragmented.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
