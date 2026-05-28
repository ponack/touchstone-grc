# SOC 2 2017 — CC7.4 Incident response.
#
# Rule (procedural surface — pragmatic v0): for every ticketing
# surface in scope (Linear workspace, Jira site), the operator must
# show one of:
#
#   1. At least one ticket labelled "security" / "incident"
#      (configurable) was closed inside the SLA window. Proves the
#      incident workflow is exercised.
#   2. An explicit attest_no_incidents=true flag on the connector,
#      signalling "we genuinely had zero security incidents this
#      window — and we're willing to say so on the record."
#
# In addition, any incident-labelled ticket that is still open and
# older than the SLA window fails the control regardless of the two
# signals above: incident response did not close the loop on time.
#
# Linear and Jira are evaluated as parallel sources — either alone
# satisfies the control, and adding both lets the operator surface
# both audit trails together.
#
# Strict reading wants every incident traceable to detection (alert
# correlation IDs) and to documented escalation. The strict layer
# lands once the alerting connectors (GuardDuty, Defender, Security
# Hub) emit stable IDs we can cross-reference against tickets.

package soc2_2017.cc7_4

import rego.v1

workspaces := [r | some r in input.resources; r.type == "linear.workspace"]
sites := [r | some r in input.resources; r.type == "jira.site"]

applicable if {
	count(workspaces) > 0
}

applicable if {
	count(sites) > 0
}

default applicable := false

# ── Violations ──────────────────────────────────────────────────────

# Linear: stale open incident tickets — older than the SLA window
# and never closed.
violations contains v if {
	some r in workspaces
	r.attrs.security_issues_open_stale_count > 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("%d incident-labelled ticket(s) in Linear workspace %q open longer than the %d-day SLA window", [r.attrs.security_issues_open_stale_count, r.attrs.workspace_name, r.attrs.sla_window_days]),
	}
}

# Linear: zero closed tickets in the window AND no operator
# attestation that the window was incident-free.
violations contains v if {
	some r in workspaces
	r.attrs.security_issues_closed_count == 0
	r.attrs.attest_no_incidents != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("Linear workspace %q has no security/incident tickets closed in the last %d days and no \"no incidents\" attestation on file", [r.attrs.workspace_name, r.attrs.sla_window_days]),
	}
}

# Jira: stale open incident tickets — older than the SLA window and
# never closed.
violations contains v if {
	some r in sites
	r.attrs.security_issues_open_stale_count > 0
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("%d incident-labelled ticket(s) in Jira site %q open longer than the %d-day SLA window", [r.attrs.security_issues_open_stale_count, r.attrs.site_url, r.attrs.sla_window_days]),
	}
}

# Jira: zero closed tickets in the window AND no operator attestation
# that the window was incident-free.
violations contains v if {
	some r in sites
	r.attrs.security_issues_closed_count == 0
	r.attrs.attest_no_incidents != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("Jira site %q has no security/incident tickets closed in the last %d days and no \"no incidents\" attestation on file", [r.attrs.site_url, r.attrs.sla_window_days]),
	}
}

# ── Outputs ─────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No ticketing surfaces (Linear/Jira) in scan input."
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

surface_count := count(workspaces) + count(sites)

message := sprintf("All %d ticketing surface(s) show working incident response within the SLA window.", [surface_count]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d incident response finding(s) — closed-in-window proof or stale ticket cleanup missing.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
