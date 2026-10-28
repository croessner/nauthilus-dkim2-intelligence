// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package projection

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// Draft-08 producer fixtures.
//
// The dkim2d-*.draft08.json responses come from the dkim2 reference
// implementation (dkim2 commit a73b2628cd5d4b0f1aee7bab315fe3bc081f5aee).
// The two-hop and single-hop files are its contrib/rspamd/tests/policy-e2e
// dkim2-two-hop-response.json and dkim2-response.json with the projection and
// hop bindings recomputed by the producer's own verifierProjectionBinding and
// verifierBoundHopBinding; the ML-DSA-44 file is the single-hop response with
// the Draft-08 Section 3.4 mldsa44 algorithm added to the hop. Each file passes
// the producer's TestPolicyE2ETwoHopProjectionBinding lock test, including its
// VerifierProjection.Valid() check.
//
// The verifier-projection-v1-binding.draft06.json and .draft07.json vectors
// are the producer goldens of the previous drafts and stay as negatives.
const (
	draft08TwoHopFixture    = "testdata/dkim2d-two-hop-response.draft08.json"
	draft08SingleHopFixture = "testdata/dkim2d-single-hop-response.draft08.json"
	draft08MLDSA44Fixture   = "testdata/dkim2d-mldsa44-single-hop-response.draft08.json"
	draft06BindingFixture   = "testdata/verifier-projection-v1-binding.draft06.json"
	draft07BindingFixture   = "testdata/verifier-projection-v1-binding.draft07.json"
)

// draft08ProducerFixtures lists every Draft-08 producer response fixture.
var draft08ProducerFixtures = []string{draft08TwoHopFixture, draft08SingleHopFixture, draft08MLDSA44Fixture}

// producerResponse is the subset of a dkim2d response that the Rspamd adapter maps into Policy facts.
type producerResponse struct {
	Verification struct {
		State                string `json:"state"`
		PrimaryReason        string `json:"primary_reason"`
		Scope                string `json:"scope"`
		HistoricalContent    string `json:"historical_content"`
		HistoricalSignatures string `json:"historical_signatures"`
		CustodyStructure     string `json:"custody_structure"`
	} `json:"verification"`
	Authentication struct {
		State         string `json:"state"`
		PrimaryReason string `json:"primary_reason"`
	} `json:"authentication"`
	Replay struct {
		Class string `json:"class"`
	} `json:"replay"`
	Policy struct {
		Mode          string `json:"mode"`
		Verdict       string `json:"verdict"`
		PrimaryReason string `json:"primary_reason"`
	} `json:"policy"`
	Disposition        string `json:"disposition"`
	VerifierProjection struct {
		Schema           string                       `json:"schema"`
		Draft            string                       `json:"draft"`
		BindingAlgorithm string                       `json:"binding_algorithm"`
		Binding          string                       `json:"binding"`
		Hops             []map[string]json.RawMessage `json:"hops"`
	} `json:"verifier_projection"`
}

// producerHopField is one chain record field in the exact order and kind emitted by the Rspamd adapter.
type producerHopField struct {
	name string
	kind pluginapi.DecisionValueKind
}

// draft08HopFields mirrors projection_hop_record of the Draft-08 Rspamd adapter.
var draft08HopFields = []producerHopField{
	{"sequence", pluginapi.DecisionValueKindInteger},
	{"message_instance", pluginapi.DecisionValueKindInteger},
	{"hop_binding", pluginapi.DecisionValueKindBytes},
	{"signer_domain", pluginapi.DecisionValueKindString},
	{"signature_algorithms", pluginapi.DecisionValueKindStrings},
	{"signature_state", pluginapi.DecisionValueKindString},
	{"custody_transition", pluginapi.DecisionValueKindString},
	{"feedback", pluginapi.DecisionValueKindBoolean},
	{"feed_here", pluginapi.DecisionValueKindBoolean},
	{"exploded", pluginapi.DecisionValueKindBoolean},
	{"recipe_mode", pluginapi.DecisionValueKindString},
	{"recipe_has_header_changes", pluginapi.DecisionValueKindBoolean},
	{"recipe_body_mode", pluginapi.DecisionValueKindString},
	{"recipe_digest", pluginapi.DecisionValueKindBytes},
	{"change_classes", pluginapi.DecisionValueKindStrings},
	{"affected_headers", pluginapi.DecisionValueKindStrings},
	{"history_header_state", pluginapi.DecisionValueKindString},
	{"history_body_state", pluginapi.DecisionValueKindString},
	{"body_availability", pluginapi.DecisionValueKindString},
	{"change_count", pluginapi.DecisionValueKindInteger},
	{"affected_header_count", pluginapi.DecisionValueKindInteger},
}

// producerRequestOptions describes deliberate deviations from the producer mapping for negative tests.
type producerRequestOptions struct {
	stringOverrides map[string]string
	extraFacts      []pluginapi.DecisionFactView
	extraHopFields  []producerHopField
	extraHopValues  map[string]json.RawMessage
}

// TestDraft08ProducerResponsesDecode proves that real Draft-08 dkim2d projections pass the complete decoder.
func TestDraft08ProducerResponsesDecode(t *testing.T) {
	for _, path := range draft08ProducerFixtures {
		t.Run(path, func(t *testing.T) {
			response := readProducerResponse(t, path)
			if response.VerifierProjection.Draft != "draft-ietf-dkim-dkim2-spec-08" {
				t.Fatalf("fixture draft = %q, want Draft-08", response.VerifierProjection.Draft)
			}

			decoded, err := Decode(producerRequest(t, response, producerRequestOptions{}))
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}

			if len(decoded.Chain) != len(response.VerifierProjection.Hops) {
				t.Fatalf("decoded %d hops, want %d", len(decoded.Chain), len(response.VerifierProjection.Hops))
			}

			wantBinding := producerBytes(t, json.RawMessage(strconv.Quote(response.VerifierProjection.Binding)))
			if !bytes.Equal(decoded.ProjectionBinding, wantBinding) {
				t.Fatal("decoded projection binding differs from the producer binding")
			}
		})
	}
}

// TestDraft08BindingsMatchProducerByteForByte recomputes every Draft-08 producer digest independently of Decode.
func TestDraft08BindingsMatchProducerByteForByte(t *testing.T) {
	for _, path := range draft08ProducerFixtures {
		t.Run(path, func(t *testing.T) {
			response := readProducerResponse(t, path)
			hops := producerHops(t, response)

			projection := CalculateProjectionBinding(hops)
			assertGoldenDigest(t, "projection", projection[:], response.VerifierProjection.Binding)

			for index, hop := range hops {
				recipe := CalculateRecipeDescriptorDigest(hop)
				if !bytes.Equal(recipe[:], hop.RecipeDigest) {
					t.Fatalf("hop %d recipe digest differs from the producer", index+1)
				}

				bound := CalculateBoundHopBinding(projection, hop)
				if !bytes.Equal(bound[:], hop.HopBinding) {
					t.Fatalf("hop %d binding = %s, want producer binding", index+1, base64.StdEncoding.EncodeToString(bound[:]))
				}
			}
		})
	}
}

// TestDraft08SingleHopFixtureMatchesBindingGolden ties the response fixture to the producer's reference golden.
func TestDraft08SingleHopFixtureMatchesBindingGolden(t *testing.T) {
	response := readProducerResponse(t, draft08SingleHopFixture)
	golden := readBindingGoldenFile(t, "testdata/verifier-projection-v1-binding.json")

	if response.VerifierProjection.Binding != golden.Expected.Projection ||
		string(response.VerifierProjection.Hops[0]["hop_binding"]) != strconv.Quote(golden.Expected.BoundHop) {
		t.Fatal("single-hop response bindings differ from the producer reference golden")
	}
}

// TestDraft08MLDSA44HopAlgorithmIsAdmitted proves the Draft-08 pure ML-DSA-44 algorithm reaches composition.
func TestDraft08MLDSA44HopAlgorithmIsAdmitted(t *testing.T) {
	decoded, err := Decode(producerRequest(t, readProducerResponse(t, draft08MLDSA44Fixture), producerRequestOptions{}))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if !slices.Contains(decoded.Chain[0].SignatureAlgorithms, "mldsa44") {
		t.Fatalf("decoded algorithms = %v, want mldsa44", decoded.Chain[0].SignatureAlgorithms)
	}
}

// TestDraft08SignatureAlgorithmVocabulary pins the closed OpenAPI VerifierHop algorithm enum.
func TestDraft08SignatureAlgorithmVocabulary(t *testing.T) {
	for _, algorithm := range []string{"ed25519-sha256", "ed25519-sha512", "mldsa44", "rsa-sha256", "rsa-sha512"} {
		if !allowedSignatureAlgorithm(algorithm) {
			t.Fatalf("allowedSignatureAlgorithm(%q) = false", algorithm)
		}
	}

	for _, algorithm := range []string{"mldsa44-ed25519-sha512", "mldsa44-ed25519-sha256", "MLDSA44", "ml-dsa-44", "unknown", ""} {
		if allowedSignatureAlgorithm(algorithm) {
			t.Fatalf("allowedSignatureAlgorithm(%q) = true", algorithm)
		}
	}
}

// TestDraft08ReplayNotEligibleIsAdmitted accepts the replay class for originator-only PASS messages.
func TestDraft08ReplayNotEligibleIsAdmitted(t *testing.T) {
	response := readProducerResponse(t, draft08SingleHopFixture)
	response.Replay.Class = "not_eligible"

	if _, err := Decode(producerRequest(t, response, producerRequestOptions{})); err != nil {
		t.Fatalf("Decode(not_eligible) error = %v", err)
	}
}

// TestDraft08VerificationReasonStates pins the Draft-08 Section 14.1 state of every OpenAPI verification reason.
func TestDraft08VerificationReasonStates(t *testing.T) {
	want := map[string][]string{
		"PASS":      {"none"},
		"TEMPERROR": {"provider_temporary"},
		"FAIL": {
			"hash_mismatch", "signature_mismatch", "timestamp_invalid", "envelope_mismatch",
			"domain_alignment_mismatch", "next_domain_mismatch", "custody_mismatch",
			"out_of_band_required", "from_not_authentic", "body_history_unavailable",
		},
		"PERMERROR": {
			"limit_exceeded", "malformed_message", "malformed_protocol", "duplicate_hash_algorithm",
			"invalid_recipe_json", "invalid_recipe", "duplicate_selector", "missing_protocol",
			"sequence_invalid", "unsupported_algorithm", "missing_key", "invalid_key", "ambiguous_key",
			"revoked_key", "unsupported_key_type", "key_algorithm_mismatch", "provider_permanent",
			"provider_contract", "internal_contract",
		},
	}

	total := 0

	for state, reasons := range want {
		total += len(reasons)

		for _, reason := range reasons {
			if got, known := verificationReasonState(reason); !known || got != state {
				t.Fatalf("verificationReasonState(%q) = %q, %t, want %q", reason, got, known, state)
			}
		}
	}

	if count := 2 + len(verificationFailReasons) + len(verificationPermerrorReasons); count != total || total != 31 {
		t.Fatalf("vocabulary has %d reasons, want the 31 OpenAPI reasons (%d listed)", count, total)
	}

	for _, reason := range []string{"too_many_signatures", "invalid_request", "duplicate_message_without_exploded", "NONE", ""} {
		if _, known := verificationReasonState(reason); known {
			t.Fatalf("verificationReasonState(%q) is known", reason)
		}
	}
}

// TestDraft08PassRequiresReasonNone rejects PASS projections whose reason Draft-08 assigns to another state.
func TestDraft08PassRequiresReasonNone(t *testing.T) {
	reasons := []string{
		"from_not_authentic", "custody_mismatch", "body_history_unavailable", "timestamp_invalid",
		"envelope_mismatch", "domain_alignment_mismatch", "next_domain_mismatch", "out_of_band_required",
		"invalid_recipe", "provider_temporary", "too_many_signatures", "protocol_pass",
	}
	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			response := readProducerResponse(t, draft08SingleHopFixture)
			response.Verification.PrimaryReason = reason
			response.Authentication.PrimaryReason = reason

			if _, err := Decode(producerRequest(t, response, producerRequestOptions{})); err == nil {
				t.Fatalf("Decode() accepted PASS with reason %q", reason)
			}
		})
	}
}

// TestDraft08NonPassVerificationFailsClosed keeps coherent Draft-08 failures out of composition.
func TestDraft08NonPassVerificationFailsClosed(t *testing.T) {
	for _, tc := range []struct{ state, reason string }{
		{"FAIL", "from_not_authentic"}, {"FAIL", "custody_mismatch"}, {"FAIL", "body_history_unavailable"},
		{"FAIL", "timestamp_invalid"}, {"PERMERROR", "invalid_recipe"}, {"TEMPERROR", "provider_temporary"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			response := readProducerResponse(t, draft08SingleHopFixture)
			response.Verification.State, response.Verification.PrimaryReason = tc.state, tc.reason
			response.Authentication.State, response.Authentication.PrimaryReason = tc.state, tc.reason
			response.Replay.Class = "not_checked"

			if _, err := Decode(producerRequest(t, response, producerRequestOptions{})); err == nil {
				t.Fatal("Decode() accepted a non-PASS verification")
			}
		})
	}
}

// TestDraft08AuthenticationCoherence mirrors the producer's replay-dependent authentication invariant.
func TestDraft08AuthenticationCoherence(t *testing.T) {
	for _, tc := range []struct {
		replay, state, reason string
		valid                 bool
	}{
		{"first_seen", "PASS", "none", true},
		{"not_checked", "PASS", "none", true},
		{"disabled", "PASS", "none", true},
		{"exploded", "PASS", "none", true},
		{"replayed", "FAIL", "duplicate_message_without_exploded", true},
		{"indeterminate", "TEMPERROR", "replay_indeterminate", true},
		{"indeterminate", "TEMPERROR", "replay_evidence_unavailable", true},
		{"first_seen", "FAIL", "custody_mismatch", false},
		{"first_seen", "PERMERROR", "invalid_recipe", false},
		{"first_seen", "PASS", "duplicate_message_without_exploded", false},
		{"replayed", "PASS", "none", false},
		{"replayed", "FAIL", "replay_indeterminate", false},
		{"indeterminate", "PASS", "none", false},
		{"indeterminate", "FAIL", "replay_indeterminate", false},
		{"indeterminate", "TEMPERROR", "provider_temporary", false},
	} {
		t.Run(tc.replay+"/"+tc.state+"/"+tc.reason, func(t *testing.T) {
			response := readProducerResponse(t, draft08SingleHopFixture)
			response.Replay.Class = tc.replay
			response.Authentication.State, response.Authentication.PrimaryReason = tc.state, tc.reason

			_, err := Decode(producerRequest(t, response, producerRequestOptions{}))
			if (err == nil) != tc.valid {
				t.Fatalf("Decode() error = %v, want valid %t", err, tc.valid)
			}
		})
	}
}

// TestOlderDraftInputFailsClosed rejects every Draft-06 and Draft-07 contract element under the Draft-08 decoder.
func TestOlderDraftInputFailsClosed(t *testing.T) {
	legacyFacts := func(t *testing.T) []pluginapi.DecisionFactView {
		t.Helper()

		return []pluginapi.DecisionFactView{
			testFact(t, "resource.dkim2.do_not_modify_state", pluginapi.DecisionFactCategoryResource, testStringValue(t, StateNotEvaluated)),
			testFact(t, "resource.dkim2.do_not_explode_state", pluginapi.DecisionFactCategoryResource, testStringValue(t, StateNotEvaluated)),
			testFact(t, "resource.dkim2.dns_testing_effective", pluginapi.DecisionFactCategoryResource, testBooleanValue(t, false)),
		}
	}

	tests := []struct {
		name    string
		options func(*testing.T) producerRequestOptions
	}{
		{name: "Draft-07 literal", options: func(*testing.T) producerRequestOptions {
			return producerRequestOptions{stringOverrides: map[string]string{"resource.dkim2.draft": "draft-ietf-dkim-dkim2-spec-07"}}
		}},
		{name: "Draft-06 literal", options: func(*testing.T) producerRequestOptions {
			return producerRequestOptions{stringOverrides: map[string]string{"resource.dkim2.draft": "draft-ietf-dkim-dkim2-spec-06"}}
		}},
		{name: "Draft-06 aggregate facts", options: func(t *testing.T) producerRequestOptions {
			return producerRequestOptions{extraFacts: legacyFacts(t)}
		}},
		{name: "Draft-06 hop flags", options: func(*testing.T) producerRequestOptions {
			return producerRequestOptions{
				extraHopFields: []producerHopField{
					{"do_not_modify", pluginapi.DecisionValueKindBoolean},
					{"do_not_explode", pluginapi.DecisionValueKindBoolean},
				},
				extraHopValues: map[string]json.RawMessage{"do_not_modify": json.RawMessage("false"), "do_not_explode": json.RawMessage("false")},
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := readProducerResponse(t, draft08TwoHopFixture)
			if _, err := Decode(producerRequest(t, response, test.options(t))); err == nil {
				t.Fatal("Decode() accepted older-draft input")
			}
		})
	}
}

// TestDraft07ProducerProjectionFailsClosed rejects a genuine Draft-07 projection: the same hop
// with the Draft-07 literal and the Draft-07 producer golden's matching bindings.
func TestDraft07ProducerProjectionFailsClosed(t *testing.T) {
	legacy := readBindingGoldenFile(t, draft07BindingFixture)
	if legacy.Draft != "draft-ietf-dkim-dkim2-spec-07" {
		t.Fatalf("legacy golden draft = %q, want Draft-07", legacy.Draft)
	}

	response := readProducerResponse(t, draft08SingleHopFixture)
	response.VerifierProjection.Draft = legacy.Draft
	response.VerifierProjection.Binding = legacy.Expected.Projection
	response.VerifierProjection.Hops[0]["hop_binding"] = json.RawMessage(strconv.Quote(legacy.Expected.BoundHop))

	if _, err := Decode(producerRequest(t, response, producerRequestOptions{})); err == nil {
		t.Fatal("Decode() accepted a Draft-07 projection")
	}
}

// TestOlderDraftBindingsFailClosed rejects producer bindings computed under Draft-06 or Draft-07.
func TestOlderDraftBindingsFailClosed(t *testing.T) {
	for _, path := range []string{draft06BindingFixture, draft07BindingFixture} {
		t.Run(path, func(t *testing.T) {
			response := readProducerResponse(t, draft08SingleHopFixture)
			legacy := readBindingGoldenFile(t, path)

			response.VerifierProjection.Binding = legacy.Expected.Projection
			response.VerifierProjection.Hops[0]["hop_binding"] = json.RawMessage(strconv.Quote(legacy.Expected.BoundHop))

			if _, err := Decode(producerRequest(t, response, producerRequestOptions{})); err == nil {
				t.Fatal("Decode() accepted older-draft bindings relabeled as Draft-08")
			}

			hops := producerHops(t, response)
			if ValidProjectionBindings(producerBytes(t, json.RawMessage(strconv.Quote(legacy.Expected.Projection))), hops) {
				t.Fatal("ValidProjectionBindings() accepted older-draft bindings")
			}
		})
	}
}

// readBindingGoldenFile strictly decodes one producer binding vector.
func readBindingGoldenFile(t *testing.T, path string) bindingGolden {
	t.Helper()

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}

	var fixture bindingGolden
	if err = json.Unmarshal(payload, &fixture); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v", path, err)
	}

	return fixture
}

// readProducerResponse strictly decodes one tracked dkim2d response fixture.
func readProducerResponse(t *testing.T, path string) producerResponse {
	t.Helper()

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}

	var response producerResponse
	if err = json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v", path, err)
	}

	return response
}

// producerRequest maps a dkim2d response exactly like the Draft-08 Rspamd policy_attributes function.
func producerRequest(t *testing.T, response producerResponse, options producerRequestOptions) pluginapi.DecisionFactRequest {
	t.Helper()

	projection := response.VerifierProjection
	target := projection.Hops[len(projection.Hops)-1]
	strings := map[string]string{
		"resource.dkim2.projection_schema":            projection.Schema,
		"resource.dkim2.draft":                        projection.Draft,
		"resource.dkim2.projection_binding_algorithm": projection.BindingAlgorithm,
		"resource.dkim2.verification_state":           response.Verification.State,
		"resource.dkim2.verification_reason":          response.Verification.PrimaryReason,
		"resource.dkim2.scope":                        response.Verification.Scope,
		"resource.dkim2.historical_content":           response.Verification.HistoricalContent,
		"resource.dkim2.historical_signatures":        response.Verification.HistoricalSignatures,
		"resource.dkim2.custody_structure":            response.Verification.CustodyStructure,
		"resource.dkim2.authentication_state":         response.Authentication.State,
		"resource.dkim2.authentication_reason":        response.Authentication.PrimaryReason,
		"resource.dkim2.replay_class":                 response.Replay.Class,
		"resource.dkim2.local_policy_mode":            response.Policy.Mode,
		"resource.dkim2.local_policy_verdict":         response.Policy.Verdict,
		"resource.dkim2.local_policy_reason":          response.Policy.PrimaryReason,
		"resource.dkim2.disposition":                  response.Disposition,
	}

	for id, value := range options.stringOverrides {
		strings[id] = value
	}

	facts := make([]pluginapi.DecisionFactView, 0, 40)
	for id, value := range strings {
		facts = append(facts, testFact(t, id, pluginapi.DecisionFactCategoryResource, testStringValue(t, value)))
	}

	facts = append(facts,
		testFact(t, "resource.dkim2.projection_binding", pluginapi.DecisionFactCategoryResource,
			testBytesValue(t, producerBytes(t, json.RawMessage(strconv.Quote(projection.Binding))))),
		testFact(t, "resource.dkim2.target_sequence", pluginapi.DecisionFactCategoryResource,
			testIntegerValue(t, producerInteger(t, target["sequence"]))),
		testFact(t, "resource.dkim2.target_message_instance", pluginapi.DecisionFactCategoryResource,
			testIntegerValue(t, producerInteger(t, target["message_instance"]))),
		testFact(t, "resource.dkim2.claimed_hop_count", pluginapi.DecisionFactCategoryResource,
			testIntegerValue(t, int64(len(projection.Hops)))),
		testFact(t, "resource.dkim2.chain", pluginapi.DecisionFactCategoryResource, producerChain(t, projection.Hops, options)),
	)
	facts = append(facts, options.extraFacts...)
	facts = append(facts, producerEnvironmentFacts(t)...)

	caller, err := pluginapi.NewDecisionCallerView(pluginapi.DecisionCallerViewInput{
		Principal: "rspamd", ClientID: "rspamd", AuthenticationKind: "policy_basic",
	})
	if err != nil {
		t.Fatalf("NewDecisionCallerView() error = %v", err)
	}

	request, err := pluginapi.NewDecisionFactRequest(ExactTarget, caller, facts)
	if err != nil {
		t.Fatalf("NewDecisionFactRequest() error = %v", err)
	}

	return request
}

// producerEnvironmentFacts reuses the canonical Rspamd environment observations of the shared request fixture.
func producerEnvironmentFacts(t *testing.T) []pluginapi.DecisionFactView {
	t.Helper()

	result := make([]pluginapi.DecisionFactView, 0, 16)

	for _, fact := range testDecisionRequest(t, "203.0.113.7").Facts() {
		if fact.Category() == pluginapi.DecisionFactCategoryEnvironment {
			result = append(result, fact)
		}
	}

	return result
}

// producerChain builds the chain record list in the producer's field order and kinds.
func producerChain(t *testing.T, hops []map[string]json.RawMessage, options producerRequestOptions) pluginapi.DecisionValue {
	t.Helper()

	fields := append(append([]producerHopField(nil), draft08HopFields...), options.extraHopFields...)
	records := make([]pluginapi.DecisionRecord, 0, len(hops))

	for _, hop := range hops {
		recordFields := make([]pluginapi.DecisionRecordField, 0, len(fields))

		for _, field := range fields {
			raw, exists := hop[field.name]
			if !exists {
				raw, exists = options.extraHopValues[field.name]
			}

			if !exists {
				t.Fatalf("producer hop misses field %s", field.name)
			}

			leaf, err := pluginapi.NewDecisionRecordFieldValue(producerValue(t, field.kind, raw))
			if err != nil {
				t.Fatalf("NewDecisionRecordFieldValue(%s) error = %v", field.name, err)
			}

			recordField, err := pluginapi.NewDecisionRecordField(field.name, leaf)
			if err != nil {
				t.Fatalf("NewDecisionRecordField(%s) error = %v", field.name, err)
			}

			recordFields = append(recordFields, recordField)
		}

		record, err := pluginapi.NewDecisionRecord(recordFields)
		if err != nil {
			t.Fatalf("NewDecisionRecord() error = %v", err)
		}

		records = append(records, record)
	}

	list, err := pluginapi.NewDecisionRecordList(records)
	if err != nil {
		t.Fatalf("NewDecisionRecordList() error = %v", err)
	}

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Records: &list})
	if err != nil {
		t.Fatalf("NewDecisionValue(records) error = %v", err)
	}

	return value
}

// producerValue converts one producer JSON member into the typed Policy value of its declared kind.
func producerValue(t *testing.T, kind pluginapi.DecisionValueKind, raw json.RawMessage) pluginapi.DecisionValue {
	t.Helper()

	switch kind {
	case pluginapi.DecisionValueKindInteger:
		return testIntegerValue(t, producerInteger(t, raw))
	case pluginapi.DecisionValueKindBytes:
		return testBytesValue(t, producerBytes(t, raw))
	case pluginapi.DecisionValueKindBoolean:
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("producer boolean: %v", err)
		}

		return testBooleanValue(t, value)
	case pluginapi.DecisionValueKindStrings:
		value := []string{}
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("producer strings: %v", err)
		}

		return testStringsValue(t, value)
	default:
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("producer string: %v", err)
		}

		return testStringValue(t, value)
	}
}

// producerInteger accepts the producer's canonical decimal-string or JSON-number integers.
func producerInteger(t *testing.T, raw json.RawMessage) int64 {
	t.Helper()

	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		text = string(raw)
	}

	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		t.Fatalf("producer integer %s: %v", raw, err)
	}

	return value
}

// producerBytes decodes one producer base64 digest.
func producerBytes(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()

	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		t.Fatalf("producer bytes: %v", err)
	}

	value, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatalf("producer base64: %v", err)
	}

	return value
}

// producerHops maps producer hops into the semantic model without using the decoder under test.
func producerHops(t *testing.T, response producerResponse) []Hop {
	t.Helper()

	result := make([]Hop, 0, len(response.VerifierProjection.Hops))
	for _, raw := range response.VerifierProjection.Hops {
		text := func(name string) string {
			var value string
			if err := json.Unmarshal(raw[name], &value); err != nil {
				t.Fatalf("hop %s: %v", name, err)
			}

			return value
		}
		list := func(name string) []string {
			value := []string{}
			if err := json.Unmarshal(raw[name], &value); err != nil {
				t.Fatalf("hop %s: %v", name, err)
			}

			return value
		}
		flag := func(name string) bool {
			var value bool
			if err := json.Unmarshal(raw[name], &value); err != nil {
				t.Fatalf("hop %s: %v", name, err)
			}

			return value
		}

		result = append(result, Hop{
			SignerDomain: text("signer_domain"), SignatureAlgorithms: list("signature_algorithms"),
			HopBinding: producerBytes(t, raw["hop_binding"]), RecipeDigest: producerBytes(t, raw["recipe_digest"]),
			ChangeClasses: list("change_classes"), AffectedHeaders: list("affected_headers"),
			SignatureState: text("signature_state"), CustodyTransition: text("custody_transition"),
			RecipeMode: text("recipe_mode"), RecipeBodyMode: text("recipe_body_mode"),
			HistoryHeaderState: text("history_header_state"), HistoryBodyState: text("history_body_state"),
			BodyAvailability: text("body_availability"), Sequence: producerInteger(t, raw["sequence"]),
			MessageInstance: producerInteger(t, raw["message_instance"]), ChangeCount: producerInteger(t, raw["change_count"]),
			AffectedHeaderCount: producerInteger(t, raw["affected_header_count"]), Feedback: flag("feedback"),
			FeedHere: flag("feed_here"), Exploded: flag("exploded"), RecipeHasHeaders: flag("recipe_has_header_changes"),
		})
	}

	return result
}
