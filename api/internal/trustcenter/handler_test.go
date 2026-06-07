package trustcenter

import (
	"testing"

	"github.com/google/uuid"
)

func TestValidSlug(t *testing.T) {
	good := []string{
		"acme",
		"acme-corp",
		"a1",
		"a-b-c-d",
		"forged-in-feathers",
	}
	for _, s := range good {
		if !validSlug(s) {
			t.Errorf("validSlug(%q) = false, want true", s)
		}
	}

	bad := []string{
		"",
		"-leading",
		"trailing-",
		"UPPER",
		"with spaces",
		"under_score",
		"--double",
		"a/b",
		// 61 chars
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	for _, s := range bad {
		if validSlug(s) {
			t.Errorf("validSlug(%q) = true, want false", s)
		}
	}
}

func TestBuildPatch_OnlyChangedFields(t *testing.T) {
	orgID := uuid.New()
	pub := true
	sets, args := buildPatch(orgID, trustCenterIn{
		Tagline:  "Forged in compliance.",
		IsPublic: &pub,
	})
	if len(sets) != 2 {
		t.Fatalf("len(sets) = %d, want 2", len(sets))
	}
	if len(args) != 3 {
		t.Fatalf("len(args) = %d, want 3 (orgID + 2 fields)", len(args))
	}
	if args[0] != orgID {
		t.Fatalf("args[0] = %v, want orgID", args[0])
	}
}

func TestBuildPatch_EmptyInputReturnsNoSets(t *testing.T) {
	orgID := uuid.New()
	sets, args := buildPatch(orgID, trustCenterIn{})
	if len(sets) != 0 {
		t.Fatalf("len(sets) = %d, want 0", len(sets))
	}
	if len(args) != 1 {
		t.Fatalf("len(args) = %d, want 1 (orgID only)", len(args))
	}
}

func TestBuildPatch_BooleanFalseStillApplies(t *testing.T) {
	orgID := uuid.New()
	pub := false
	sets, _ := buildPatch(orgID, trustCenterIn{IsPublic: &pub})
	if len(sets) != 1 {
		t.Fatalf("len(sets) = %d, want 1 (false is a real change)", len(sets))
	}
}

func TestDisplayName_FallsBackToOrgSlug(t *testing.T) {
	tc := trustCenterOut{OrgSlug: "acme"}
	if got := displayName(tc); got != "acme" {
		t.Fatalf("displayName = %q, want %q", got, "acme")
	}
	name := "ACME Corp"
	tc.DisplayName = &name
	if got := displayName(tc); got != "ACME Corp" {
		t.Fatalf("displayName = %q, want %q", got, "ACME Corp")
	}
}
