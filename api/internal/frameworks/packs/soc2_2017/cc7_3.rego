# SOC 2 2017 — CC7.3 Security event analysis.
#
# Rule (GuardDuty surface): security events are analyzed when there
# is a service collecting + analyzing them. GuardDuty performs that
# analysis continuously, so an ENABLED detector is the strongest
# AWS-native signal.
#
# CC7.3 also expects human review of findings, which is procedural
# evidence beyond what an automated scan can capture. The control
# pack will gain a procedural-evidence connector in Phase 3+ for
# that part; for v0 we evaluate the technical precondition.
#
# Applicability: same shape as CC6.8 — any aws.* resource means we
# audited AWS, absence of detectors when AWS was scanned is a real
# failure.

package soc2_2017.cc7_3

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

any_disabled_detector if {
	some d in detectors
	not enabled_detector(d)
}

# ── Violations ──────────────────────────────────────────────────────

violations contains v if {
	applicable
	count(detectors) == 0
	v := {
		"resource_type": "aws.guardduty",
		"resource_id":   "(account)",
		"reason":        "no GuardDuty detectors configured — no automated security event analysis in place",
	}
}

violations contains v if {
	applicable
	some d in detectors
	not enabled_detector(d)
	v := {
		"resource_type": d.type,
		"resource_id":   d.id,
		"reason":        sprintf("GuardDuty detector status is %q — analysis pipeline is not active", [d.attrs.status]),
	}
}

# ── Outputs ─────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No AWS resources in scan input."
default failures := []

failures := [v | some v in violations]

status := "fail" if {
	applicable
	count(detectors) == 0
}

status := "fail" if {
	applicable
	any_disabled_detector
}

status := "pass" if {
	applicable
	has_enabled_detector
	not any_disabled_detector
}

message := "No GuardDuty detectors — automated security event analysis is not configured." if {
	applicable
	count(detectors) == 0
}

message := sprintf("%d GuardDuty detector(s) not in ENABLED state — analysis pipeline gap.", [count([d | some d in detectors; not enabled_detector(d)])]) if {
	applicable
	count(detectors) > 0
	any_disabled_detector
}

message := "GuardDuty is actively analyzing security events." if {
	applicable
	has_enabled_detector
	not any_disabled_detector
}
