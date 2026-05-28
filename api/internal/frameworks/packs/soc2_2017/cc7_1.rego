# SOC 2 2017 — CC7.1 Vulnerability detection.
#
# Evaluates two cloud-native vulnerability-detection surfaces:
#
#   AWS Security Hub             Hub enabled + at least one
#                                 compliance standard subscribed
#                                 (CIS / AWS Foundational / PCI-DSS /
#                                 NIST 800-53 — each includes
#                                 vulnerability rules).
#   Defender for Cloud           At least one Standard-tier plan
#                                 (Defender for Servers + Defender
#                                 CSPM ship vulnerability assessment).
#
# Future extensions: AWS Inspector (direct vuln scanning), Config
# conformance packs (drift detection), Defender vulnerability
# assessment results.

package soc2_2017.cc7_1

import rego.v1

# ── AWS Security Hub ────────────────────────────────────────────────

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

# ── Microsoft Defender for Cloud ────────────────────────────────────

defender_plans := [r | some r in input.resources; r.type == "azure.defender.pricing"]

azure_scanned if {
	some r in input.resources
	startswith(r.type, "azure.")
}

default azure_scanned := false

has_enabled_defender if {
	some p in defender_plans
	p.attrs.enabled == true
}

violations contains v if {
	azure_scanned
	count(defender_plans) == 0
	v := {
		"resource_type": "azure.defender",
		"resource_id":   "(subscription)",
		"reason":        "no Microsoft Defender for Cloud pricing plans returned for this subscription",
	}
}

violations contains v if {
	azure_scanned
	count(defender_plans) > 0
	not has_enabled_defender
	v := {
		"resource_type": "azure.defender",
		"resource_id":   "(subscription)",
		"reason":        "all Defender for Cloud plans are on the Free tier — no active vulnerability detection pipeline",
	}
}

# ── Applicability + outputs ─────────────────────────────────────────

default applicable := false

applicable if aws_scanned
applicable if azure_scanned

default status := "not_applicable"
default message := "No cloud resources in scan input."
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

message := sprintf("%d vulnerability-detection finding(s) across configured clouds.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "Every audited cloud has an active vulnerability-detection pipeline." if {
	applicable
	count(violations) == 0
}
