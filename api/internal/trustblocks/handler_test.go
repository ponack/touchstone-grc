package trustblocks

import "testing"

func TestMergeUpdate_PreservesExistingWhenInputEmpty(t *testing.T) {
	existing := blockOut{
		Heading:      "Data handling",
		BodyMarkdown: "We store customer data in AWS us-east-1.",
		Position:     3,
		IsPublic:     true,
	}
	merged := mergeUpdate(existing, blockIn{})
	if merged.Heading != "Data handling" || merged.BodyMarkdown != "We store customer data in AWS us-east-1." {
		t.Fatalf("content not preserved: %+v", merged)
	}
	if merged.Position != 3 || merged.IsPublic != true {
		t.Fatalf("position/is_public not preserved: %+v", merged)
	}
}

func TestMergeUpdate_OverridesProvidedFields(t *testing.T) {
	priv := false
	newPos := 7
	merged := mergeUpdate(blockOut{Heading: "A", Position: 0, IsPublic: true}, blockIn{
		Heading:  "B",
		Position: &newPos,
		IsPublic: &priv,
	})
	if merged.Heading != "B" {
		t.Fatalf("Heading override failed: %q", merged.Heading)
	}
	if merged.Position != 7 {
		t.Fatalf("Position override failed: %d", merged.Position)
	}
	if merged.IsPublic != false {
		t.Fatalf("IsPublic override failed")
	}
}

func TestMergeUpdate_TrimsWhitespace(t *testing.T) {
	merged := mergeUpdate(blockOut{}, blockIn{
		Heading:      "  Spaced heading  ",
		BodyMarkdown: "  # body  ",
	})
	if merged.Heading != "Spaced heading" {
		t.Fatalf("Heading not trimmed: %q", merged.Heading)
	}
	if merged.BodyMarkdown != "# body" {
		t.Fatalf("BodyMarkdown not trimmed: %q", merged.BodyMarkdown)
	}
}

func TestNeighborCmpAndOrder(t *testing.T) {
	if neighborCmp("up") != "<" {
		t.Errorf("neighborCmp(up) = %q, want <", neighborCmp("up"))
	}
	if neighborCmp("down") != ">" {
		t.Errorf("neighborCmp(down) = %q, want >", neighborCmp("down"))
	}
	if neighborOrder("up") != "DESC" {
		t.Errorf("neighborOrder(up) = %q, want DESC", neighborOrder("up"))
	}
	if neighborOrder("down") != "ASC" {
		t.Errorf("neighborOrder(down) = %q, want ASC", neighborOrder("down"))
	}
	if edgeLabel("up") != "top" {
		t.Errorf("edgeLabel(up) = %q, want top", edgeLabel("up"))
	}
	if edgeLabel("down") != "bottom" {
		t.Errorf("edgeLabel(down) = %q, want bottom", edgeLabel("down"))
	}
}
