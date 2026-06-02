# PCI DSS v4.0 — 11.3.1 Internal vulnerability scans are performed.
#
# Touchstone reads AWS Security Hub as the automated vulnerability
# detection signal: the hub must be enabled in at least one region
# AND at least one compliance standard must be subscribed (CIS / AWS
# Foundational / PCI-DSS / NIST 800-53 standards each carry vuln
# checks).
#
# Same evidence as SOC 2 CC7.1's AWS surface.

package pci_dss_v4.req_11_3_1

import rego.v1

hubs := [r | some r in input.resources; r.type == "aws.securityhub.hub"]

applicable if {
	count(hubs) > 0
}

default applicable := false

has_active_hub if {
	some h in hubs
	count(h.attrs.subscribed_standards) > 0
}

violations contains v if {
	applicable
	not has_active_hub
	v := {
		"resource_type": "aws.securityhub",
		"resource_id":   "(account)",
		"reason":        "Security Hub is enabled but no compliance standards are subscribed",
	}
}

default status := "not_applicable"
default message := "No Security Hub resources in scan input."
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

message := "Security Hub provides automated vulnerability scanning with at least one compliance standard subscribed." if {
	applicable
	count(violations) == 0
}

message := "Security Hub is enabled but no compliance standards are subscribed — no automated vulnerability scanning is active." if {
	applicable
	count(violations) > 0
}
