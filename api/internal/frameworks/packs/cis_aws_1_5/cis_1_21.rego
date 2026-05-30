# CIS AWS 1.5 — 1.21 Ensure that IAM Access Analyzer is enabled for
# all regions.
#
# The scanner emits one aws.accessanalyzer.region resource per
# configured region, with has_active_analyzer pre-computed. Any
# region in scope without an active analyzer is a finding.
#
# "All regions" is bounded by the operator's configured region list
# — the Touchstone connector only scans regions an operator has
# declared. Adding a region to scope expands what CIS 1.21 evaluates.

package cis_aws_1_5.cis_1_21

import rego.v1

regions := [r | some r in input.resources; r.type == "aws.accessanalyzer.region"]

applicable if {
	count(regions) > 0
}

default applicable := false

violations contains v if {
	some r in regions
	r.attrs.has_active_analyzer != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("region %q has no active IAM Access Analyzer", [r.attrs.region]),
	}
}

default status := "not_applicable"
default message := "No Access Analyzer region resources in scan input."
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

message := sprintf("All %d configured region(s) carry an active IAM Access Analyzer.", [count(regions)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d region(s) without an active Access Analyzer.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
