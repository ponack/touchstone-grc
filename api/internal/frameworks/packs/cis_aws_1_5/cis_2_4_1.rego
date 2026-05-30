# CIS AWS 1.5 — 2.4.1 Ensure that encryption is enabled for EFS file
# systems.
#
# EFS encryption is set at file-system creation; it cannot be turned
# on later. Every aws.efs.file_system in scope must carry
# encrypted=true.

package cis_aws_1_5.cis_2_4_1

import rego.v1

fss := [r | some r in input.resources; r.type == "aws.efs.file_system"]

applicable if {
	count(fss) > 0
}

default applicable := false

violations contains v if {
	some r in fss
	r.attrs.encrypted != true
	v := {
		"resource_type": r.type,
		"resource_id":   r.id,
		"reason":        sprintf("EFS file system %q (%s) is not encrypted at rest", [r.attrs.name, r.attrs.file_system_id]),
	}
}

default status := "not_applicable"
default message := "No EFS file systems in scan input."
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

message := sprintf("All %d EFS file system(s) are encrypted at rest.", [count(fss)]) if {
	applicable
	count(violations) == 0
}

message := sprintf("%d EFS file system(s) are not encrypted at rest.", [count(violations)]) if {
	applicable
	count(violations) > 0
}
