# PCI DSS v4.0 — 11.5.1 Intrusion-detection / prevention techniques
# are used to detect and prevent intrusions into the network.
#
# Touchstone reads AWS GuardDuty as the IDS/IPS signal: at least one
# detector must exist AND be ENABLED. Same evidence as SOC 2 CC6.8 /
# CC7.3.
#
# Equivalent surfaces on Azure (Defender for Cloud) and GCP
# (Security Command Center) are evaluated by other rules; this PCI
# entry currently scopes to the AWS GuardDuty stream — extend with
# cross-cloud signals in a follow-up.

package pci_dss_v4.req_11_5_1

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
		"reason":        "no GuardDuty detector is ENABLED — no IDS/IPS coverage on the AWS surface",
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

message := "GuardDuty provides active IDS/IPS coverage." if {
	applicable
	count(violations) == 0
}

message := "No active GuardDuty detector — IDS/IPS coverage is missing on AWS." if {
	applicable
	count(violations) > 0
}
