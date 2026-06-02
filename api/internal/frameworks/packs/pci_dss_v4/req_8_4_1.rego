# PCI DSS v4.0 — 8.4.1 MFA implemented for all access into the CDE.
#
# Every administrative identity must require a second factor.
# Touchstone evaluates two surfaces:
#
#   AWS IAM users   — console-enabled users carry at least one MFA
#                      device (mirrors CIS 1.10 / SOC 2 CC6.1).
#   Azure AD users  — Member accounts that are MFA-capable have
#                      registered an MFA method (mirrors SOC 2
#                      CC6.1's Azure surface).

package pci_dss_v4.req_8_4_1

import rego.v1

aws_users := [r | some r in input.resources; r.type == "aws.iam.user"]
azure_users := [r | some r in input.resources; r.type == "azure.ad.user"]

aws_console_users := [r | some r in aws_users; r.attrs.has_console == true]

applicable if {
	count(aws_console_users) > 0
}
applicable if {
	count(azure_users) > 0
}

default applicable := false

# ── AWS console users ──────────────────────────────────────────────

violations contains v if {
	some r in aws_console_users
	count(r.attrs.mfa_devices) == 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("console-enabled IAM user %q has no MFA device", [r.attrs.user_name]),
	}
}

# ── Azure AD users ─────────────────────────────────────────────────

violations contains v if {
	some r in azure_users
	r.attrs.user_type == "Member"
	r.attrs.is_mfa_capable == true
	r.attrs.is_mfa_registered != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "Azure AD member is MFA-capable but has not registered any MFA method",
	}
}

# ── Outputs ────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No identity resources in scan input."
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

message := "All console-enabled identities carry MFA." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d MFA finding(s) across configured identity providers.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
