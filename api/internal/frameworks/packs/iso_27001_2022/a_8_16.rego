# ISO/IEC 27001:2022 Annex A — A.8.16 Monitoring activities.
#
# Networks, systems and applications shall be monitored for
# anomalous behaviour and appropriate actions taken to evaluate
# potential information security incidents.
#
# Touchstone evaluates the integrated AWS monitoring pipeline:
#
#   - GuardDuty has at least one ENABLED detector (threat
#     detection across CloudTrail / VPC Flow / DNS).
#   - Security Hub is enabled with at least one compliance
#     standard subscribed (continuous posture monitoring).
#
# Both must be live — A.8.16 is the cross-cutting pipeline check,
# distinct from A.8.7 (malware-specific framing) and A.8.8
# (vulnerability information). Same evidence composite as
# SOC 2 CC7.2 + CC7.3.

package iso_27001_2022.a_8_16

import rego.v1

detectors := [r | some r in input.resources; r.type == "aws.guardduty.detector"]
hubs := [r | some r in input.resources; r.type == "aws.securityhub.hub"]

aws_scanned if {
	some r in input.resources
	startswith(r.type, "aws.")
}

default aws_scanned := false

has_enabled_detector if {
	some d in detectors
	d.attrs.status == "ENABLED"
}

has_active_hub if {
	some h in hubs
	count(h.attrs.subscribed_standards) > 0
}

violations contains v if {
	aws_scanned
	not has_enabled_detector
	v := {
		"resource_type": "aws.guardduty",
		"resource_id":   "(account)",
		"reason":        "no GuardDuty detector is ENABLED — anomaly-detection half of the monitoring pipeline is missing",
	}
}

violations contains v if {
	aws_scanned
	not has_active_hub
	v := {
		"resource_type": "aws.securityhub",
		"resource_id":   "(account)",
		"reason":        "Security Hub is not enabled with any subscribed standards — posture-monitoring half of the monitoring pipeline is missing",
	}
}

applicable if aws_scanned

default applicable := false

default status := "not_applicable"
default message := "No AWS resources in scan input."
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

message := "AWS monitoring pipeline is active end-to-end — GuardDuty (detection) and Security Hub (posture) both live." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d monitoring-pipeline finding(s) — integrated monitoring of networks / systems / applications is incomplete.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
