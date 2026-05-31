# CIS AWS 1.5 — 3.5 Ensure AWS Config is enabled in all regions.
#
# Every region in the operator's scope must carry at least one AWS
# Config recorder that (a) records all supported resources and (b)
# is currently in the "Recording" state. The scanner pre-computes
# has_active_recorder so the rego inspects a single boolean.
#
# Mirrors the CIS 1.21 Access Analyzer per-region shape.

package cis_aws_1_5.cis_3_5

import rego.v1

regions := [r | some r in input.resources; r.type == "aws.config.region"]

applicable if {
	count(regions) > 0
}

default applicable := false

violations contains v if {
	some r in regions
	r.attrs.has_active_recorder != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("region %q has no active AWS Config recorder covering all supported resources", [r.attrs.region]),
	}
}

default status := "not_applicable"
default message := "No AWS Config region resources in scan input."
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

message := sprintf("All %d configured region(s) carry an active AWS Config recorder.", [count(regions)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d region(s) without an active Config recorder.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
