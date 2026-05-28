# SOC 2 2017 — CC6.2 New user access provisioning.
#
# Rule (GitHub surface — pragmatic v0): every GitHub organization in
# scope must require two-factor authentication AND have zero members
# without 2FA enabled.
#
# This is the "pragmatic v0" of CC6.2 — the control's strict reading
# wants every account-add event traceable to a documented workflow
# (closed onboarding ticket, signed approval, SSO provisioning). That
# strict reading needs the GitHub audit-log connector plus a
# Jira/Linear connector, which land in follow-up PRs. The MFA
# enforcement check here catches ~80% of CC6.2 intent and is what
# auditors typically accept as evidence of a working access program.
#
# Applicability fires when at least one github.org resource is in
# scan input. Accounts with no GitHub yields not_applicable —
# CC6.2's procedural side is evaluated by other connectors as they
# ship.

package soc2_2017.cc6_2

import rego.v1

orgs := [r | some r in input.resources; r.type == "github.org"]

applicable if {
	count(orgs) > 0
}

default applicable := false

# ── Violations ──────────────────────────────────────────────────────

# Org does not require 2FA at all.
violations contains v if {
	some r in orgs
	r.attrs.two_factor_requirement_enabled != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("GitHub organization %q does not require two-factor authentication", [r.attrs.login]),
	}
}

# Org requires 2FA in policy, but at least one member is still
# without it. Possible when the org enabled the requirement after
# adding members and never re-enforced.
violations contains v if {
	some r in orgs
	r.attrs.two_factor_requirement_enabled == true
	r.attrs.members_without_2fa_count > 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("%d GitHub member(s) in %q still lack 2FA despite the org-level requirement", [r.attrs.members_without_2fa_count, r.attrs.login]),
	}
}

# ── Outputs ─────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No GitHub organizations in scan input."
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

message := sprintf("All %d GitHub organization(s) require 2FA and have no members without it.", [count(orgs)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d GitHub MFA finding(s) — provisioning workflow missing the foundational enforcement.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
