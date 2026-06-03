# ISO/IEC 27001:2022 Annex A — A.8.7 Protection against malware.
#
# Protection against malware shall be implemented and supported by
# appropriate user awareness.
#
# Touchstone's automated signal: AWS GuardDuty must have at least
# one ENABLED detector. Same evidence as SOC 2 CC6.8 / PCI 11.5.1 /
# HIPAA 164.308(a)(5)(ii)(B).

package iso_27001_2022.a_8_7

import rego.v1

detectors := [r | some r in input.resources; r.type == "aws.guardduty.detector"]

applicable if {
	count(detectors) > 0
}

default applicable := false

has_enabled_detector if {
	some d in detectors
	d.attrs.status == "ENABLED"
}

violations contains v if {
	applicable
	not has_enabled_detector
	v := {
		"resource_type": "aws.guardduty",
		"resource_id":   "(account)",
		"reason":        "no GuardDuty detector is ENABLED — no automated malicious-software detection on the AWS surface",
	}
}

default status := "not_applicable"
default message := "No GuardDuty detectors in scan input."
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

message := "GuardDuty provides active malicious-software detection." if {
	applicable
	count(violations) == 0
}

message := "No active GuardDuty detector — malicious-software detection coverage is missing on AWS." if {
	applicable
	count(violations) > 0
}
