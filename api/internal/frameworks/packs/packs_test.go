package packs

import (
	"io/fs"
	"testing"
)

// TestEmbedHasSOC2 verifies the embed directive picked up the SOC 2
// manifest and its policy directory. Without this check, a typo or
// renamed file would silently ship an empty FS at build time.
func TestEmbedHasSOC2(t *testing.T) {
	if _, err := fs.Stat(FS, "soc2_2017.yaml"); err != nil {
		t.Fatalf("soc2_2017.yaml not in embedded FS: %v", err)
	}

	want := []string{
		"soc2_2017/cc6_1.rego",
		"soc2_2017/cc6_2.rego",
		"soc2_2017/cc6_3.rego",
		"soc2_2017/cc6_6.rego",
		"soc2_2017/cc6_7.rego",
		"soc2_2017/cc6_8.rego",
		"soc2_2017/cc7_1.rego",
		"soc2_2017/cc7_2.rego",
		"soc2_2017/cc7_3.rego",
		"soc2_2017/cc7_4.rego",
		"soc2_2017/cc7_5.rego",
	}
	for _, path := range want {
		if _, err := fs.Stat(FS, path); err != nil {
			t.Errorf("missing from embedded FS: %s (%v)", path, err)
		}
	}
}
