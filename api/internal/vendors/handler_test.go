package vendors

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizeTags_DedupAndCase(t *testing.T) {
	got := normalizeTags([]string{"PII", " pii ", "soc2", "", "TIER-1", "tier-1"})
	want := []string{"pii", "soc2", "tier-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeTags = %v, want %v", got, want)
	}
}

func TestNormalizeTags_NilToEmptySlice(t *testing.T) {
	got := normalizeTags(nil)
	if got == nil || len(got) != 0 {
		t.Fatalf("normalizeTags(nil) = %v, want []string{}", got)
	}
}

func TestMergeUpdate_PreservesExistingWhenInputEmpty(t *testing.T) {
	existing := vendorOut{
		Name:        "Stripe",
		VendorType:  "saas",
		Criticality: "high",
		Status:      "active",
	}
	merged := mergeUpdate(existing, vendorIn{})
	if merged.Name != "Stripe" || merged.Criticality != "high" {
		t.Fatalf("fields not preserved: %+v", merged)
	}
}

func TestMergeUpdate_ClassificationClearWithNoneSentinel(t *testing.T) {
	cls := "confidential"
	existing := vendorOut{DataClassification: &cls}
	merged := mergeUpdate(existing, vendorIn{DataClassification: "none"})
	if merged.DataClassification != nil {
		t.Fatalf("DataClassification not cleared: %v", *merged.DataClassification)
	}
}

func TestMergeUpdate_ClassificationSetFromEmptyToValue(t *testing.T) {
	existing := vendorOut{}
	merged := mergeUpdate(existing, vendorIn{DataClassification: "restricted"})
	if merged.DataClassification == nil || *merged.DataClassification != "restricted" {
		t.Fatalf("DataClassification not set: %+v", merged)
	}
}

func TestMergeUpdate_OwnerSwap(t *testing.T) {
	oldOwner := uuid.New()
	newOwner := uuid.New()
	existing := vendorOut{OwnerID: &oldOwner}
	merged := mergeUpdate(existing, vendorIn{OwnerID: &newOwner})
	if merged.OwnerID == nil || *merged.OwnerID != newOwner {
		t.Fatalf("OwnerID not swapped")
	}
}

func TestMergeUpdate_DateFieldsOverride(t *testing.T) {
	onboard := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	nextReview := time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)
	merged := mergeUpdate(vendorOut{}, vendorIn{
		OnboardedDate:  &onboard,
		NextReviewDate: &nextReview,
	})
	if merged.OnboardedDate == nil || !merged.OnboardedDate.Equal(onboard) {
		t.Fatalf("OnboardedDate = %v, want %v", merged.OnboardedDate, onboard)
	}
	if merged.NextReviewDate == nil || !merged.NextReviewDate.Equal(nextReview) {
		t.Fatalf("NextReviewDate = %v, want %v", merged.NextReviewDate, nextReview)
	}
}

func TestValidateEnums_DefaultsApplied(t *testing.T) {
	crit, status, err := validateEnums(vendorIn{VendorType: "saas"})
	if err != nil {
		t.Fatalf("validateEnums error: %v", err)
	}
	if crit != "medium" {
		t.Errorf("crit = %q, want medium (default)", crit)
	}
	if status != "active" {
		t.Errorf("status = %q, want active (default)", status)
	}
}

func TestValidateEnums_RejectsUnknownVendorType(t *testing.T) {
	if _, _, err := validateEnums(vendorIn{VendorType: "consultancy"}); err == nil {
		t.Fatalf("validateEnums accepted unknown vendor_type")
	}
}

func TestValidVendorTypesCoverage(t *testing.T) {
	for _, k := range []string{"saas", "paas", "iaas", "processor", "subprocessor", "hardware", "professional_services", "other"} {
		if _, ok := validVendorTypes[k]; !ok {
			t.Errorf("missing vendor_type %q", k)
		}
	}
	if _, ok := validVendorTypes["consultancy"]; ok {
		t.Errorf("unexpected vendor_type 'consultancy' is valid")
	}
}
