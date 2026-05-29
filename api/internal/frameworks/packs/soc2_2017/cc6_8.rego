# SOC 2 2017 — CC6.8 Malicious software prevention.
#
# Evaluates three cloud-native threat-detection surfaces:
#
#   AWS GuardDuty                      Detector status per region
#   Microsoft Defender for Cloud       At least one plan in Standard
#                                      pricing tier (active) in the
#                                      subscription
#   GCP Security Command Center        Project-scoped SCC subscription
#                                      reachable (Event Threat Detection,
#                                      VM Threat Detection, etc.)
#
# Each cloud is evaluated independently. Future extensions (AWS
# Inspector, Defender for Servers MDE configuration, SSM-deployed
# anti-malware, third-party EDR) will broaden this control.

package soc2_2017.cc6_8

import rego.v1

# ── AWS GuardDuty ───────────────────────────────────────────────────

detectors := [r | some r in input.resources; r.type == "aws.guardduty.detector"]

aws_scanned if {
	some r in input.resources
	startswith(r.type, "aws.")
}

default aws_scanned := false

enabled_detector(d) if {
	d.attrs.status == "ENABLED"
}

has_enabled_detector if {
	some d in detectors
	enabled_detector(d)
}

any_disabled_detector if {
	some d in detectors
	not enabled_detector(d)
}

violations contains v if {
	aws_scanned
	count(detectors) == 0
	v := {
		"resource_type": "aws.guardduty",
		"resource_id":   "(account)",
		"reason":        "no GuardDuty detectors configured for this account",
	}
}

violations contains v if {
	aws_scanned
	some d in detectors
	not enabled_detector(d)
	v := {
		"resource_type": d.type,
		"resource_id":   d.id,
		"reason":        sprintf("GuardDuty detector status is %q (must be ENABLED)", [d.attrs.status]),
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
		"reason":        "no Microsoft Defender for Cloud pricing plans were returned for this subscription",
	}
}

violations contains v if {
	azure_scanned
	count(defender_plans) > 0
	not has_enabled_defender
	v := {
		"resource_type": "azure.defender",
		"resource_id":   "(subscription)",
		"reason":        "all Defender for Cloud plans are on the Free tier — no active threat detection",
	}
}

# ── GCP Security Command Center ─────────────────────────────────────

scc_subs := [r | some r in input.resources; r.type == "gcp.scc.subscription"]

gcp_scanned if {
	some r in input.resources
	startswith(r.type, "gcp.")
}

default gcp_scanned := false

has_active_scc if {
	some s in scc_subs
	s.attrs.is_active == true
}

violations contains v if {
	gcp_scanned
	count(scc_subs) == 0
	v := {
		"resource_type": "gcp.scc",
		"resource_id":   "(project)",
		"reason":        "no Security Command Center subscription evidence was collected for this project",
	}
}

violations contains v if {
	gcp_scanned
	count(scc_subs) > 0
	not has_active_scc
	some s in scc_subs
	v := {
		"resource_type": s.type,
		"resource_id":   s.id,
		"reason":        "Security Command Center is not active for this project — no managed threat detection (Event Threat Detection, VM Threat Detection)",
	}
}

# ── Applicability + outputs ─────────────────────────────────────────

default applicable := false

applicable if aws_scanned
applicable if azure_scanned
applicable if gcp_scanned

default status := "not_applicable"
default message := "No cloud resources in scan input."
default failures := []

failures := [v | some v in violations]

status := "fail" if {
	applicable
	count(violations) > 0
}

status := "pass" if {
	applicable
	count(violations) == 0
}

message := sprintf("%d malicious-software-prevention finding(s) across configured clouds.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "Every audited cloud has active threat detection." if {
	applicable
	count(violations) == 0
}
