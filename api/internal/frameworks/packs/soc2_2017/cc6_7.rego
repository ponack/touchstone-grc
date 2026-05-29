# SOC 2 2017 — CC6.7 Restricted data transmission / encryption.
#
# Evaluates three surfaces:
#
#   AWS S3              every bucket must have default encryption enabled
#                       (AES256, aws:kms, or aws:kms:dsse — anything but
#                       "no encryption configured").
#   Azure Storage       every account must reject HTTP at the wire
#                       (supportsHttpsTrafficOnly == true) and refuse
#                       ciphers older than TLS 1.2.
#   GCP Cloud Storage   platform enforces both default at-rest encryption
#                       and HTTPS-only access — buckets surface here only
#                       to anchor applicability. CMEK enforcement
#                       (encryption.defaultKmsKeyName presence) is a
#                       stricter follow-up control, tracked separately.
#
# Azure auto-encrypts every storage account at rest with platform-
# managed keys — there is no "encryption disabled" failure mode to
# check on Azure side. CMK enforcement (encryption.key_source ==
# "Microsoft.Keyvault") is a stricter follow-up control.
#
# TLS-only enforcement on S3 (denying non-HTTPS via bucket policy
# Condition: aws:SecureTransport=false) is a future extension that
# requires parsing the bucket policy document. Tracked separately.

package soc2_2017.cc6_7

import rego.v1

# ── AWS S3 violations ───────────────────────────────────────────────

violations contains v if {
	some r in input.resources
	r.type == "aws.s3.bucket"
	r.attrs.encryption.enabled != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "default encryption is not configured",
	}
}

# ── Azure Storage violations ────────────────────────────────────────

violations contains v if {
	some r in input.resources
	r.type == "azure.storage.account"
	r.attrs.enable_https_traffic_only != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        "supportsHttpsTrafficOnly is not enabled — account accepts HTTP",
	}
}

# Anything below TLS 1.2 is a fail. Azure currently allows
# configuring TLS1_0, TLS1_1, TLS1_2, TLS1_3. Missing string is
# treated as the platform default (TLS1_2) so it passes silently.
violations contains v if {
	some r in input.resources
	r.type == "azure.storage.account"
	r.attrs.minimum_tls_version != ""
	not tls_version_ok(r.attrs.minimum_tls_version)
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("minimum_tls_version is %q — must be TLS1_2 or higher", [r.attrs.minimum_tls_version]),
	}
}

tls_version_ok(v) if v == "TLS1_2"
tls_version_ok(v) if v == "TLS1_3"

# ── Applicability ───────────────────────────────────────────────────

applicable if {
	some r in input.resources
	r.type == "aws.s3.bucket"
}
applicable if {
	some r in input.resources
	r.type == "azure.storage.account"
}
applicable if {
	some r in input.resources
	r.type == "gcp.storage.bucket"
}

default applicable := false

# ── Outputs ─────────────────────────────────────────────────────────

default status := "not_applicable"
default message := "No storage resources in scan input."
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

message := sprintf("%d encryption / transit finding(s) across configured storage surfaces.", [count(violations)]) if {
	applicable
	count(violations) > 0
}

message := "All storage resources enforce encryption + TLS." if {
	applicable
	count(violations) == 0
}
