# ISO/IEC 27001:2022 Annex A — A.8.8 Management of technical
# vulnerabilities.
#
# Information about technical vulnerabilities of information systems
# in use shall be obtained, the organization's exposure to such
# vulnerabilities shall be evaluated, and appropriate measures shall
# be taken.
#
# Touchstone's automated signal: AWS Security Hub must be enabled
# with at least one compliance standard subscribed (CIS / AWS
# Foundational / PCI-DSS / NIST 800-53 — each ships vulnerability
# rules). Same evidence as SOC 2 CC7.1.

package iso_27001_2022.a_8_8

import rego.v1

hubs := [r | some r in input.resources; r.type == "aws.securityhub.hub"]

aws_scanned if {
	some r in input.resources
	startswith(r.type, "aws.")
}

default aws_scanned := false

hub_with_standards(h) if {
	count(h.attrs.subscribed_standards) > 0
}

has_active_hub if {
	some h in hubs
	hub_with_standards(h)
}

violations contains v if {
	aws_scanned
	count(hubs) == 0
	v := {
		"resource_type": "aws.securityhub",
		"resource_id":   "(account)",
		"reason":        "AWS Security Hub is not enabled in any configured region",
	}
}

violations contains v if {
	aws_scanned
	count(hubs) > 0
	not has_active_hub
	some h in hubs
	v := {
		"resource_type": h.type,
		"resource_id":   h.id,
		"reason":        "Security Hub is enabled but no compliance standards are subscribed",
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

message := "AWS Security Hub is active with subscribed standards — technical-vulnerability information is being obtained continuously." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d technical-vulnerability finding(s) — vulnerability information pipeline incomplete.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
