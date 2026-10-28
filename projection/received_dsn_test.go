package projection

import (
	"slices"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestVerifierProjectionAcceptsOnlyDeclaredOptionalDSNPropagation admits exactly the Draft-08 propagation vocabulary;
// the dkim2d /v1/dsn/sign unsigned reasons are a REST header, never a projection value.
func TestVerifierProjectionAcceptsOnlyDeclaredOptionalDSNPropagation(t *testing.T) {
	want := []string{
		"not_applicable", "eligible", "terminal_origin", "not_failure", "forbidden_null_previous_sender",
		"forbidden_identity_misaligned", "unsupported_chain", "not_reconstructable", "not_evaluated",
	}
	if !slices.Equal(receivedDSNPropagations, want) {
		t.Fatalf("receivedDSNPropagations = %v, want %v", receivedDSNPropagations, want)
	}

	rejected := []string{"unknown", "unsigned_original", "delivery_status_identity_unavailable", "delivery_status_from_not_authentic", ""}
	states := append(slices.Clone(receivedDSNPropagations), rejected...)

	for _, state := range states {
		request := appendRequestFact(t, testDecisionRequest(t, "192.0.2.25"), testFact(t, "resource.dkim2.received_dsn_propagation", pluginapi.DecisionFactCategoryResource, testStringValue(t, state)))

		_, err := Decode(request)
		if (err == nil) == slices.Contains(rejected, state) {
			t.Fatalf("optional DSN %s: %v", state, err)
		}
	}
}

// TestVerifierProjectionRejectsMalformedOptionalDSN preserves the declared type and host-assigned category.
func TestVerifierProjectionRejectsMalformedOptionalDSN(t *testing.T) {
	for _, tc := range []struct {
		name     string
		category pluginapi.DecisionFactCategory
		value    pluginapi.DecisionValue
	}{
		{"wrong category", pluginapi.DecisionFactCategoryEnvironment, testStringValue(t, "eligible")},
		{"wrong type", pluginapi.DecisionFactCategoryResource, testBooleanValue(t, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := appendRequestFact(t, testDecisionRequest(t, "192.0.2.25"), testFact(t, "resource.dkim2.received_dsn_propagation", tc.category, tc.value))
			if _, err := Decode(request); err == nil {
				t.Fatal("malformed optional DSN accepted")
			}
		})
	}
}
