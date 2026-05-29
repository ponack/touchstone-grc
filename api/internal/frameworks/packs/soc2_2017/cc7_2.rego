# SOC 2 2017 — CC7.2 System monitoring.
#
# Evaluates three surfaces:
#
#   AWS CloudTrail   At least one trail must be multi-region, include
#                    global service events, have log file validation
#                    enabled, and be actively logging.
#   Azure Monitor    At least one subscription-level diagnostic
#                    setting must forward the Activity Log to a
#                    long-term sink (Log Analytics, Storage, or
#                    Event Hub) AND have Administrative + Security
#                    log categories enabled.
#   GCP Cloud Logging
#                    At least one enabled non-default log sink must
#                    capture admin activity audit logs and route them
#                    to a durable export (BigQuery, GCS, or Pub/Sub).
#                    The built-in _Default / _Required sinks don't
#                    count — they only write to the in-project
#                    Logging bucket.
#
# Each cloud is evaluated independently. If a scan touched AWS, AWS
# monitoring must be in place; same for Azure and GCP. A scan
# covering only one cloud does not need findings from the others to
# pass.

package soc2_2017.cc7_2

import rego.v1

# ── AWS CloudTrail ──────────────────────────────────────────────────

trails := [r | some r in input.resources; r.type == "aws.cloudtrail.trail"]

aws_scanned if {
	some r in input.resources
	startswith(r.type, "aws.")
}

default aws_scanned := false

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

violations contains v if {
	aws_scanned
	count(trails) == 0
	v := {
		"resource_type": "aws.cloudtrail",
		"resource_id":   "(account)",
		"reason":        "no CloudTrail trails are configured for this account",
	}
}

violations contains v if {
	aws_scanned
	count(trails) > 0
	not has_compliant_trail
	some t in trails
	v := {
		"resource_type": t.type,
		"resource_id":   t.id,
		"reason": sprintf(
			"trail does not meet all monitoring requirements (multi_region=%v, global_service_events=%v, log_file_validation=%v, is_logging=%v)",
			[t.attrs.is_multi_region, t.attrs.include_global_service_events, t.attrs.log_file_validation_enabled, t.attrs.is_logging],
		),
	}
}

# ── Azure Activity Log diagnostic settings ──────────────────────────

azure_settings := [r | some r in input.resources; r.type == "azure.monitor.activity_log_setting"]

azure_scanned if {
	some r in input.resources
	startswith(r.type, "azure.")
}

default azure_scanned := false

compliant_setting(s) if {
	has_any_sink(s)
	s.attrs.categories.Administrative == true
	s.attrs.categories.Security == true
}

has_any_sink(s) if s.attrs.has_workspace_sink == true
has_any_sink(s) if s.attrs.has_storage_sink == true
has_any_sink(s) if s.attrs.has_eventhub_sink == true

has_compliant_azure_setting if {
	some s in azure_settings
	compliant_setting(s)
}

violations contains v if {
	azure_scanned
	count(azure_settings) == 0
	v := {
		"resource_type": "azure.monitor.activity_log_setting",
		"resource_id":   "(subscription)",
		"reason":        "no subscription-level diagnostic setting forwards the Activity Log to a long-term sink",
	}
}

violations contains v if {
	azure_scanned
	count(azure_settings) > 0
	not has_compliant_azure_setting
	some s in azure_settings
	v := {
		"resource_type": s.type,
		"resource_id":   s.id,
		"reason": sprintf(
			"diagnostic setting does not meet all monitoring requirements (workspace=%v, storage=%v, eventhub=%v, Administrative=%v, Security=%v)",
			[s.attrs.has_workspace_sink, s.attrs.has_storage_sink, s.attrs.has_eventhub_sink, s.attrs.categories.Administrative, s.attrs.categories.Security],
		),
	}
}

# ── GCP Cloud Logging sinks ─────────────────────────────────────────

gcp_sinks := [r | some r in input.resources; r.type == "gcp.logging.sink"]

gcp_scanned if {
	some r in input.resources
	startswith(r.type, "gcp.")
}

default gcp_scanned := false

compliant_gcp_sink(s) if {
	s.attrs.captures_admin_activity == true
	s.attrs.is_durable_export == true
}

has_compliant_gcp_sink if {
	some s in gcp_sinks
	compliant_gcp_sink(s)
}

violations contains v if {
	gcp_scanned
	count(gcp_sinks) == 0
	v := {
		"resource_type": "gcp.logging.sink",
		"resource_id":   "(project)",
		"reason":        "no Cloud Logging sink exports admin activity audit logs to a durable destination (BigQuery, GCS, or Pub/Sub)",
	}
}

violations contains v if {
	gcp_scanned
	count(gcp_sinks) > 0
	not has_compliant_gcp_sink
	some s in gcp_sinks
	v := {
		"resource_type": s.type,
		"resource_id":   s.id,
		"reason": sprintf(
			"sink does not meet all monitoring requirements (captures_admin_activity=%v, is_durable_export=%v, destination_type=%v)",
			[s.attrs.captures_admin_activity, s.attrs.is_durable_export, s.attrs.destination_type],
		),
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

message := sprintf("%d monitoring finding(s) across configured clouds.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "Monitoring is configured for every audited cloud." if {
	applicable
	count(violations) == 0
}
