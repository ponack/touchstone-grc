# SOC 2 2017 — CC7.3 Security event analysis.
#
# Evaluates the same three surfaces as CC6.8 because in each cloud the
# threat-detection service IS the analysis pipeline:
#
#   AWS GuardDuty                 ENABLED detector = active analysis
#   Microsoft Defender for Cloud  At least one Standard-tier plan
#   GCP Security Command Center   Project-scoped SCC subscription
#                                  reachable = active analysis pipeline
#
# CC7.3 also expects human review of findings — procedural evidence
# beyond what an automated scan can capture. The control pack will
# gain a procedural-evidence connector later; for v0 the technical
# precondition is what we evaluate.

package soc2_2017.cc7_3

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
		"reason":        "no GuardDuty detectors configured — no automated security event analysis in place",
	}
}

violations contains v if {
	aws_scanned
	some d in detectors
	not enabled_detector(d)
	v := {
		"resource_type": d.type,
		"resource_id":   d.id,
		"reason":        sprintf("GuardDuty detector status is %q — analysis pipeline is not active", [d.attrs.status]),
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
		"reason":        "all Defender for Cloud plans are on the Free tier — no active security event analysis",
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
		"reason":        "Security Command Center is not active for this project — no managed security event analysis pipeline",
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

message := sprintf("%d security-event-analysis finding(s) across configured clouds.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "Every audited cloud is actively analyzing security events." if {
	applicable
	count(violations) == 0
}
