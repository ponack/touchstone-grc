# PCI DSS v4.0 — 4.2.1 Strong cryptography and security protocols
# protect PAN during transmission.
#
# Account data must travel over strong, modern crypto only. Touchstone
# evaluates two surfaces:
#
#   AWS S3        — bucket policy denies aws:SecureTransport=false
#                    (mirrors CIS 2.1.2)
#   Azure Storage — supportsHttpsTrafficOnly==true AND
#                    minimum_tls_version is TLS1_2 or TLS1_3
#                    (mirrors SOC 2 CC6.7's Azure surface)

package pci_dss_v4.req_4_2_1

import rego.v1

buckets := [r | some r in input.resources; r.type == "aws.s3.bucket"]
azure_storage := [r | some r in input.resources; r.type == "azure.storage.account"]

applicable if {
	count(buckets) > 0
}
applicable if {
	count(azure_storage) > 0
}

default applicable := false

# ── S3 ─────────────────────────────────────────────────────────────

violations contains v if {
	some r in buckets
	r.attrs.enforces_https_only != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("S3 bucket %q does not deny non-HTTPS requests in its policy", [r.attrs.name]),
	}
}

# ── Azure Storage ──────────────────────────────────────────────────

violations contains v if {
	some r in azure_storage
	r.attrs.enable_https_traffic_only != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "Azure storage account allows HTTP traffic (supportsHttpsTrafficOnly is false)",
	}
}

violations contains v if {
	some r in azure_storage
	r.attrs.minimum_tls_version != ""
	not tls_ok(r.attrs.minimum_tls_version)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("Azure storage minimum_tls_version is %q (must be TLS1_2 or TLS1_3)", [r.attrs.minimum_tls_version]),
	}
}

tls_ok(v) if v == "TLS1_2"
tls_ok(v) if v == "TLS1_3"

# ── Outputs ────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No transit-encryption surfaces in scan input."
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

message := "All transit surfaces enforce strong cryptography." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d transit-encryption finding(s) across S3 / Azure storage.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
