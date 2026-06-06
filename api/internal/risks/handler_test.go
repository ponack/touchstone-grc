package risks

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

func TestValidateEnums_DefaultsApplied(t *testing.T) {
	cat, ilL, ilI, rlL, rlI, treat, status, err := validateEnums(riskIn{Title: "X"})
	if err != nil {
		t.Fatalf("validateEnums error: %v", err)
	}
	if cat != "security" {
		t.Errorf("cat = %q, want security (default)", cat)
	}
	if ilL != "medium" || ilI != "medium" || rlL != "medium" || rlI != "medium" {
		t.Errorf("levels = %q/%q/%q/%q, want medium (default)", ilL, ilI, rlL, rlI)
	}
	if treat != "mitigate" {
		t.Errorf("treat = %q, want mitigate (default)", treat)
	}
	if status != "identified" {
		t.Errorf("status = %q, want identified (default)", status)
	}
}

func TestValidateEnums_RejectsUnknownCategory(t *testing.T) {
	if _, _, _, _, _, _, _, err := validateEnums(riskIn{RiskCategory: "geopolitics"}); err == nil {
		t.Fatalf("validateEnums accepted unknown risk_category")
	}
}

func TestValidateEnums_RejectsUnknownLevel(t *testing.T) {
	if _, _, _, _, _, _, _, err := validateEnums(riskIn{InherentLikelihood: "extreme"}); err == nil {
		t.Fatalf("validateEnums accepted unknown likelihood level")
	}
}

func TestValidCategoriesCoverage(t *testing.T) {
	for _, k := range []string{"operational", "security", "privacy", "compliance", "financial", "reputational", "strategic", "third_party", "other"} {
		if _, ok := validCategories[k]; !ok {
			t.Errorf("missing category %q", k)
		}
	}
	if _, ok := validCategories["geopolitics"]; ok {
		t.Errorf("unexpected category 'geopolitics' is valid")
	}
}

func TestMergeUpdate_PreservesExistingWhenInputEmpty(t *testing.T) {
	existing := riskOut{
		Title:              "Stripe API key leak",
		RiskCategory:       "third_party",
		InherentLikelihood: "high",
		InherentImpact:     "critical",
		Status:             "treating",
	}
	merged := mergeUpdate(existing, riskIn{})
	if merged.Title != "Stripe API key leak" || merged.RiskCategory != "third_party" {
		t.Fatalf("fields not preserved: %+v", merged)
	}
	if merged.InherentLikelihood != "high" || merged.InherentImpact != "critical" {
		t.Fatalf("levels not preserved: %+v", merged)
	}
}

func TestMergeUpdate_OverridesProvidedFields(t *testing.T) {
	existing := riskOut{
		Title:              "Stripe API key leak",
		ResidualLikelihood: "high",
		ResidualImpact:     "high",
		Status:             "treating",
	}
	merged := mergeUpdate(existing, riskIn{
		ResidualLikelihood: "low",
		ResidualImpact:     "medium",
		Status:             "accepted",
	})
	if merged.ResidualLikelihood != "low" || merged.ResidualImpact != "medium" {
		t.Fatalf("residual override failed: %+v", merged)
	}
	if merged.Status != "accepted" {
		t.Fatalf("status override failed: %+v", merged)
	}
}

func TestMergeUpdate_OwnershipSwap(t *testing.T) {
	oldOwner := uuid.New()
	newOwner := uuid.New()
	existing := riskOut{OwnerID: &oldOwner}
	merged := mergeUpdate(existing, riskIn{OwnerID: &newOwner})
	if merged.OwnerID == nil || *merged.OwnerID != newOwner {
		t.Fatalf("OwnerID not swapped")
	}
}

func TestMergeUpdate_DateFields(t *testing.T) {
	closed := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	merged := mergeUpdate(riskOut{}, riskIn{ClosedDate: &closed, Status: "closed"})
	if merged.ClosedDate == nil || !merged.ClosedDate.Equal(closed) {
		t.Fatalf("ClosedDate = %v, want %v", merged.ClosedDate, closed)
	}
	if merged.Status != "closed" {
		t.Fatalf("Status = %q, want closed", merged.Status)
	}
}
