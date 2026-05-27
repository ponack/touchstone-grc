# SOC 2 2017 — CC7.2 System monitoring.
#
# Rule: the AWS account must have at least one CloudTrail trail that
# satisfies *every* monitoring requirement:
#
#   - Multi-region (captures activity in every region, not just home)
#   - Includes global service events (IAM, STS, CloudFront, etc.)
#   - Log file validation enabled (tamper-detection via SHA-256 digests)
#   - Currently logging (IsLogging=true at scan time)
#
# A trail that is missing ANY of those is not sufficient on its own;
# the rego treats it as a violation listing what's missing.
#
# Applicability: any AWS resource in scan input means we audited AWS,
# so CC7.2 applies. Absence of trails when AWS was scanned is the
# strongest possible signal that monitoring is not in place.

package soc2_2017.cc7_2

import rego.v1

# Set of CloudTrail trails in scan input.
trails := [r | some r in input.resources; r.type == "aws.cloudtrail.trail"]

# Did this scan touch AWS at all?
aws_scanned if {
	some r in input.resources
	startswith(r.type, "aws.")
}

default aws_scanned := false
default applicable := false

applicable if aws_scanned

# A trail that meets every monitoring requirement.
compliant_trail(t) if {
	t.attrs.is_multi_region == true
	t.attrs.include_global_service_events == true
	t.attrs.log_file_validation_enabled == true
	t.attrs.is_logging == true
}

has_compliant_trail if {
	some t in trails
	compliant_trail(t)
}

# ── Violations ──────────────────────────────────────────────────────

# No trails at all when AWS was scanned.
violations contains v if {
	applicable
	count(trails) == 0
	v := {
		"resource_type": "aws.cloudtrail",
		"resource_id":   "(account)",
		"reason":        "no CloudTrail trails are configured for this account",
	}
}

# Trails exist but none satisfies every requirement.
violations contains v if {
	applicable
	count(trails) > 0
	not has_compliant_trail
	some t in trails
	v := {
		"resource_type": t.type,
		"resource_id":   t.id,
		"reason":        sprintf(
			"trail does not meet all monitoring requirements (multi_region=%v, global_service_events=%v, log_file_validation=%v, is_logging=%v)",
			[t.attrs.is_multi_region, t.attrs.include_global_service_events, t.attrs.log_file_validation_enabled, t.attrs.is_logging],
		),
	}
}

# ── Outputs ─────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No AWS resources in scan input."
default failures := []

failures := [v | some v in violations]

status := "pass" if {
	applicable
	has_compliant_trail
}

status := "fail" if {
	applicable
	not has_compliant_trail
}

message := "At least one CloudTrail trail meets every monitoring requirement." if {
	applicable
	has_compliant_trail
}

message := "No CloudTrail trail meets every monitoring requirement (multi-region + global events + log validation + actively logging)." if {
	applicable
	not has_compliant_trail
	count(trails) > 0
}

message := "No CloudTrail trails are configured for this account." if {
	applicable
	count(trails) == 0
}
