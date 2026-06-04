package assets

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeTags_DedupAndCase(t *testing.T) {
	got := normalizeTags([]string{"PCI", " pci ", "ephi", "", "TIER-1", "tier-1"})
	want := []string{"pci", "ephi", "tier-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeTags = %v, want %v", got, want)
	}
}

func TestNormalizeTags_EmptyStaysEmptySlice(t *testing.T) {
	got := normalizeTags(nil)
	if got == nil {
		t.Fatalf("normalizeTags(nil) returned nil — should return empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("normalizeTags(nil) length = %d, want 0", len(got))
	}
}

func TestMergeUpdate_PreservesExistingWhenInputEmpty(t *testing.T) {
	existing := assetOut{
		Name:        "api",
		AssetType:   "service",
		Environment: "production",
		Criticality: "high",
		Status:      "active",
	}
	merged := mergeUpdate(existing, assetIn{})
	if merged.Name != "api" || merged.Criticality != "high" {
		t.Fatalf("fields not preserved: %+v", merged)
	}
}

func TestMergeUpdate_OverridesProvidedFields(t *testing.T) {
	existing := assetOut{
		Name:        "api",
		AssetType:   "service",
		Environment: "production",
		Criticality: "medium",
		Status:      "active",
	}
	merged := mergeUpdate(existing, assetIn{
		Criticality: "critical",
		Status:      "decommissioned",
	})
	if merged.Criticality != "critical" || merged.Status != "decommissioned" {
		t.Fatalf("override failed: %+v", merged)
	}
	if merged.Name != "api" {
		t.Fatalf("untouched field clobbered: %+v", merged)
	}
}

func TestMergeUpdate_ClassificationClearWithNoneSentinel(t *testing.T) {
	cls := "confidential"
	existing := assetOut{Classification: &cls}
	merged := mergeUpdate(existing, assetIn{Classification: "none"})
	if merged.Classification != nil {
		t.Fatalf("Classification not cleared: %v", *merged.Classification)
	}
}

func TestMergeUpdate_ClassificationSetFromEmptyToValue(t *testing.T) {
	existing := assetOut{}
	merged := mergeUpdate(existing, assetIn{Classification: "restricted"})
	if merged.Classification == nil || *merged.Classification != "restricted" {
		t.Fatalf("Classification not set: %+v", merged)
	}
}

func TestMergeUpdate_OwnerSwap(t *testing.T) {
	oldOwner := uuid.New()
	newOwner := uuid.New()
	existing := assetOut{OwnerID: &oldOwner}
	merged := mergeUpdate(existing, assetIn{OwnerID: &newOwner})
	if merged.OwnerID == nil || *merged.OwnerID != newOwner {
		t.Fatalf("OwnerID not swapped")
	}
}

func TestValidAssetTypes(t *testing.T) {
	for _, k := range []string{"application", "service", "database", "repository", "data_store", "cloud_account", "infrastructure", "device", "other"} {
		if _, ok := validAssetTypes[k]; !ok {
			t.Errorf("missing asset_type %q", k)
		}
	}
	if _, ok := validAssetTypes["computer"]; ok {
		t.Errorf("unexpected asset_type 'computer' is valid")
	}
}
