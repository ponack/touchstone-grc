package personnel

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMergeUpdate_PreservesExistingWhenInputEmpty(t *testing.T) {
	existing := personOut{
		FullName: "Alice Example",
		Email:    "alice@example.com",
		Role:     "Engineer",
		Status:   "active",
	}
	merged := mergeUpdate(existing, personIn{})
	if merged.FullName != "Alice Example" {
		t.Fatalf("FullName = %q, want preserved", merged.FullName)
	}
	if merged.Status != "active" {
		t.Fatalf("Status = %q, want preserved", merged.Status)
	}
}

func TestMergeUpdate_OverridesProvidedFields(t *testing.T) {
	existing := personOut{
		FullName: "Alice Example",
		Email:    "alice@example.com",
		Role:     "Engineer",
		Status:   "active",
	}
	end := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	merged := mergeUpdate(existing, personIn{
		Role:    "Senior Engineer",
		Status:  "terminated",
		EndDate: &end,
	})
	if merged.Role != "Senior Engineer" {
		t.Fatalf("Role = %q, want override", merged.Role)
	}
	if merged.Status != "terminated" {
		t.Fatalf("Status = %q, want override", merged.Status)
	}
	if merged.EndDate == nil || !merged.EndDate.Equal(end) {
		t.Fatalf("EndDate = %v, want %v", merged.EndDate, end)
	}
}

func TestMergeUpdate_KeepsManagerWhenAbsent(t *testing.T) {
	mgr := uuid.New()
	existing := personOut{ManagerID: &mgr}
	merged := mergeUpdate(existing, personIn{})
	if merged.ManagerID == nil || *merged.ManagerID != mgr {
		t.Fatalf("ManagerID dropped on no-op update")
	}
}

func TestValidStatuses(t *testing.T) {
	for _, s := range []string{"active", "on_leave", "terminated"} {
		if _, ok := validStatuses[s]; !ok {
			t.Errorf("missing valid status %q", s)
		}
	}
	if _, ok := validStatuses["fired"]; ok {
		t.Errorf("unexpected status 'fired' is valid")
	}
}
