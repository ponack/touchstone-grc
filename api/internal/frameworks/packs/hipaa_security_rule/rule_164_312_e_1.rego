# HIPAA Security Rule — 164.312(e)(1) Transmission Security.
#
# Required standard: implement technical security measures to guard
# against unauthorized access to ePHI that is being transmitted over
# an electronic communications network.
#
# Touchstone evaluates two surfaces (same shape as PCI 4.2.1):
#
#   AWS S3        — bucket policy denies aws:SecureTransport=false
#   Azure Storage — supportsHttpsTrafficOnly==true AND
#                    minimum_tls_version >= TLS1_2

package hipaa_security_rule.rule_164_312_e_1

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

violations contains v if {
	some r in buckets
	r.attrs.enforces_https_only != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("S3 bucket %q does not deny non-HTTPS requests in its policy", [r.attrs.name]),
	}
}

violations contains v if {
	some r in azure_storage
	r.attrs.enable_https_traffic_only != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "Azure storage account allows HTTP traffic",
	}
}

violations contains v if {
	some r in azure_storage
	r.attrs.minimum_tls_version != ""
	not tls_ok(r.attrs.minimum_tls_version)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("Azure storage minimum_tls_version is %q (must be TLS1_2 or higher)", [r.attrs.minimum_tls_version]),
	}
}

tls_ok(v) if v == "TLS1_2"
tls_ok(v) if v == "TLS1_3"

default status := "not_applicable"
default message := "No transmission surfaces in scan input."
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

message := "All ePHI transmission surfaces enforce strong cryptography." if {
	applicable
	count(violations) == 0
}

message := sprintf("%d transmission-security finding(s) on ePHI surfaces.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
