# SOC 2 2017 — CC7.1 Vulnerability detection.
#
# Rule (Security Hub surface): the account must have AWS Security
# Hub enabled with at least one compliance standard subscribed. The
# CIS AWS Foundations Benchmark and AWS Foundational Security Best
# Practices both include vulnerability-detection rules (Inspector
# findings, KMS rotation, IMDSv2, etc.), so a subscribed standard
# = an active vulnerability-detection pipeline.
#
# Future extensions: AWS Inspector (direct vuln scanning, surfaces
# CVE matches against running EC2 + ECR images), AWS Config
# conformance packs (drift detection).
#
# Applicability: any aws.* in scan input means we audited AWS. If
# AWS was scanned but no Hub appears in the resource list, that's a
# real failure — Security Hub is not enabled in any of the configured
# regions.

package soc2_2017.cc7_1

import rego.v1

hubs := [r | some r in input.resources; r.type == "aws.securityhub.hub"]

aws_scanned if {
	some r in input.resources
	startswith(r.type, "aws.")
}

default aws_scanned := false
default applicable := false

applicable if aws_scanned

# A "compliant" Hub has at least one standard subscribed. An enabled
# Hub with no standards is just an empty inbox.
hub_with_standards(h) if {
	count(h.attrs.subscribed_standards) > 0
}

has_active_hub if {
	some h in hubs
	hub_with_standards(h)
}

# ── Violations ──────────────────────────────────────────────────────

violations contains v if {
	applicable
	count(hubs) == 0
	v := {
		"resource_type": "aws.securityhub",
		"resource_id":   "(account)",
		"reason":        "AWS Security Hub is not enabled in any configured region",
	}
}

violations contains v if {
	applicable
	count(hubs) > 0
	not has_active_hub
	some h in hubs
	v := {
		"resource_type": h.type,
		"resource_id":   h.id,
		"reason":        "Security Hub is enabled but no compliance standards are subscribed",
	}
}

# ── Outputs ─────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No AWS resources in scan input."
default failures := []

failures := [v | some v in violations]

status := "pass" if {
	applicable
	has_active_hub
}

status := "fail" if {
	applicable
	not has_active_hub
}

message := "Security Hub is active with at least one compliance standard subscribed." if {
	applicable
	has_active_hub
}

message := "Security Hub is not enabled in any configured region." if {
	applicable
	count(hubs) == 0
}

message := "Security Hub is enabled but no compliance standards are subscribed." if {
	applicable
	count(hubs) > 0
	not has_active_hub
}
