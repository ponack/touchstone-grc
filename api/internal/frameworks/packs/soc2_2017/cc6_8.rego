# SOC 2 2017 — CC6.8 Malicious software prevention.
#
# Rule (GuardDuty surface): the account must have GuardDuty
# detectors enabled. Findings indicate active threat detection /
# anomaly analysis, which the auditor accepts as evidence that
# malicious software / compromised credentials would be surfaced.
#
# Future extensions (AWS Inspector for vuln scanning, anti-malware
# enforced via SSM, third-party EDR) will broaden this control.
# This v0 evaluation captures the highest-signal AWS-native source.
#
# Applicability: any aws.* resource in scan input means we audited
# AWS, so CC6.8 applies. Absence of detectors when AWS was scanned
# is a real failure, not "not_applicable".

package soc2_2017.cc6_8

import rego.v1

detectors := [r | some r in input.resources; r.type == "aws.guardduty.detector"]

aws_scanned if {
	some r in input.resources
	startswith(r.type, "aws.")
}

default aws_scanned := false
default applicable := false

applicable if aws_scanned

enabled_detector(d) if {
	d.attrs.status == "ENABLED"
}

has_enabled_detector if {
	some d in detectors
	enabled_detector(d)
}

# ── Violations ──────────────────────────────────────────────────────

# No detectors at all.
violations contains v if {
	applicable
	count(detectors) == 0
	v := {
		"resource_type": "aws.guardduty",
		"resource_id":   "(account)",
		"reason":        "no GuardDuty detectors configured for this account",
	}
}

# Detectors exist but at least one is not ENABLED. Surfaces each
# disabled detector individually so the operator sees where coverage
# is missing.
violations contains v if {
	applicable
	some d in detectors
	not enabled_detector(d)
	v := {
		"resource_type": d.type,
		"resource_id":   d.id,
		"reason":        sprintf("GuardDuty detector status is %q (must be ENABLED)", [d.attrs.status]),
	}
}

# ── Outputs ─────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No AWS resources in scan input."
default failures := []

failures := [v | some v in violations]

# Fail when no detectors exist at all, OR when any existing detector
# is disabled. We do not require every region; that strictness is
# tracked separately. Detectors that ARE enabled count as evidence
# of an active program.
status := "fail" if {
	applicable
	count(detectors) == 0
}

status := "fail" if {
	applicable
	some d in detectors
	not enabled_detector(d)
}

status := "pass" if {
	applicable
	has_enabled_detector
	not any_disabled_detector
}

any_disabled_detector if {
	some d in detectors
	not enabled_detector(d)
}

message := "No GuardDuty detectors are configured for this account." if {
	applicable
	count(detectors) == 0
}

message := sprintf("%d GuardDuty detector(s) are not in ENABLED state.", [count([d | some d in detectors; not enabled_detector(d)])]) if {
	applicable
	count(detectors) > 0
	any_disabled_detector
}

message := "All GuardDuty detectors are ENABLED." if {
	applicable
	has_enabled_detector
	not any_disabled_detector
}
