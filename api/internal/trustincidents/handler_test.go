package trustincidents

import (
	"testing"
	"time"
)

func TestValidateEnums_DefaultsApplied(t *testing.T) {
	status, severity, err := validateEnums(incidentIn{})
	if err != nil {
		t.Fatalf("validateEnums error: %v", err)
	}
	if status != "ongoing" {
		t.Errorf("status = %q, want ongoing (default)", status)
	}
	if severity != "medium" {
		t.Errorf("severity = %q, want medium (default)", severity)
	}
}

func TestValidateEnums_RejectsUnknownStatus(t *testing.T) {
	if _, _, err := validateEnums(incidentIn{Status: "fubar"}); err == nil {
		t.Fatalf("validateEnums accepted unknown status")
	}
}

func TestValidateEnums_RejectsUnknownSeverity(t *testing.T) {
	if _, _, err := validateEnums(incidentIn{Severity: "catastrophic"}); err == nil {
		t.Fatalf("validateEnums accepted unknown severity")
	}
}

func TestValidStatusesCoverage(t *testing.T) {
	for _, k := range []string{"ongoing", "monitoring", "resolved"} {
		if _, ok := validStatuses[k]; !ok {
			t.Errorf("missing status %q", k)
		}
	}
	if _, ok := validStatuses["fubar"]; ok {
		t.Errorf("unexpected status 'fubar' is valid")
	}
}

func TestMergeUpdate_PreservesExistingWhenInputEmpty(t *testing.T) {
	existing := incidentOut{
		Title:    "S3 outage 2026-06-01",
		Status:   "resolved",
		Severity: "high",
		IsPublic: true,
	}
	merged := mergeUpdate(existing, incidentIn{})
	if merged.Title != "S3 outage 2026-06-01" || merged.Status != "resolved" {
		t.Fatalf("fields not preserved: %+v", merged)
	}
	if merged.IsPublic != true {
		t.Fatalf("IsPublic not preserved: %+v", merged)
	}
}

func TestMergeUpdate_OverridesProvidedFields(t *testing.T) {
	priv := false
	merged := mergeUpdate(incidentOut{Status: "ongoing", IsPublic: true}, incidentIn{
		Status:   "resolved",
		IsPublic: &priv,
	})
	if merged.Status != "resolved" {
		t.Fatalf("Status override failed: %+v", merged)
	}
	if merged.IsPublic != false {
		t.Fatalf("IsPublic override failed: %+v", merged)
	}
}

func TestMergeUpdate_ResolvedAtSwaps(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	merged := mergeUpdate(incidentOut{}, incidentIn{ResolvedAt: &now})
	if merged.ResolvedAt == nil || !merged.ResolvedAt.Equal(now) {
		t.Fatalf("ResolvedAt = %v, want %v", merged.ResolvedAt, now)
	}
}
