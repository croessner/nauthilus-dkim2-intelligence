package main

import (
	"strings"
	"testing"
)

// TestChainAndPeerSchemasHaveExactIndependentVocabulary protects the normative composition boundary.
func TestChainAndPeerSchemasHaveExactIndependentVocabulary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []fieldSpec
		count  int
	}{
		{"chain", chainFields(), 32}, {"peer", peerFields(), 36},
	} {
		if len(tc.fields) != tc.count {
			t.Fatalf("%s fields=%d want %d", tc.name, len(tc.fields), tc.count)
		}

		seen := make(map[string]bool)
		for _, field := range tc.fields {
			if seen[field.Name] {
				t.Fatalf("duplicate %s field %s", tc.name, field.Name)
			}

			seen[field.Name] = true
			if field.Name == "ip" || field.Name == "subject_tag" || field.Name == "recipe_digest" {
				t.Fatal("sensitive material duplicated")
			}
		}
	}
}

// TestDraft07OutputsExcludeRetiredProtectionFlags keeps the Draft-06 donotmodify/donotexplode surface out of the composition.
func TestDraft07OutputsExcludeRetiredProtectionFlags(t *testing.T) {
	for _, field := range chainFields() {
		if field.Name == "do_not_modify" || field.Name == "do_not_explode" {
			t.Fatalf("chain output still declares retired field %s", field.Name)
		}
	}

	catalog := violationCatalog()
	if len(catalog) != 12 {
		t.Fatalf("violation catalog has %d classes, want 12", len(catalog))
	}

	for _, class := range catalog {
		if strings.HasPrefix(class, "do_not_") {
			t.Fatalf("violation catalog still contains retired class %s", class)
		}
	}
}
