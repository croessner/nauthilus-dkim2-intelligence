// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//go:build dkim2policyharness

package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/configinput"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const dkim2AssessmentProviderID = "dkim2/plugin.dkim2_intelligence.assessment"

// dkim2PolicyFileEnv names an optional Policy document that replaces the
// reference example, so deployments can run the scenarios against their own
// DKIM2 namespace.
const dkim2PolicyFileEnv = "NAUTHILUS_DKIM2_POLICY_FILE"

const (
	dkim2TestSMTPPeerIP   = "203.0.113.77"
	dkim2TestSignerDomain = "sensitive-signer.example"
)

// assertDKIM2DiagnosticsDoNotLeak verifies that public diagnostics never project request identities.
func assertDKIM2DiagnosticsDoNotLeak(t *testing.T, response decision.DecisionResponse) {
	t.Helper()

	diagnostics := response.Diagnostics()
	if diagnostics == nil {
		t.Fatal("diagnostics are missing")
	}

	payload := fmt.Sprint(diagnostics.Entries().Values())

	for _, secret := range []string{dkim2TestSMTPPeerIP, dkim2TestSignerDomain} {
		if strings.Contains(payload, secret) {
			t.Fatalf("diagnostics leak %q: %s", secret, payload)
		}
	}
}

// assertDKIM2ReferenceProviderFacts verifies the fake provider uses the configured output contract.
func assertDKIM2ReferenceProviderFacts(
	t *testing.T,
	schema policyruntime.CompiledSchema,
	outputs []providedFact,
) {
	t.Helper()

	provenance, err := decision.NewProvenance(decision.FactSourcePlugin, "dkim2_intelligence", dkim2AssessmentProviderID)
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	for _, output := range outputs {
		normalized, normalizeErr := schema.NormalizeValue(output.id, output.value)
		if normalizeErr != nil {
			t.Fatalf("NormalizeValue(%s) error = %v", output.id, normalizeErr)
		}

		fact, factErr := decision.NewFact(output.id, output.category, normalized, provenance)
		if factErr != nil {
			t.Fatalf("NewFact(%s) error = %v", output.id, factErr)
		}

		facts, factsErr := decision.NewFactSet([]decision.Fact{fact})
		if factsErr != nil {
			t.Fatalf("NewFactSet(%s) error = %v", output.id, factsErr)
		}

		if validateErr := schema.ValidatePresentFacts(facts); validateErr != nil {
			t.Fatalf("ValidatePresentFacts(%s) error = %v", output.id, validateErr)
		}
	}
}

// evaluateDKIM2Reference runs one configured final-decision checkpoint.
func evaluateDKIM2Reference(
	t *testing.T,
	catalog *policyruntime.TargetCatalog,
	target decision.Target,
	provider *countingFactProvider,
	verificationState string,
	factOverrides map[string]any,
) runtimeEvaluation {
	t.Helper()

	evaluator, err := newCheckpointRuntime(checkpointRuntimeConfig{
		catalog: catalog,
		factProviders: map[string]factProviderBinding{
			dkim2AssessmentProviderID: {
				provider: provider, source: decision.FactSourcePlugin,
				authority: "dkim2_intelligence", component: dkim2AssessmentProviderID,
			},
			"dkim2/plugin.geoip.smtp_peer":       {provider: &countingFactProvider{}, source: decision.FactSourcePlugin, authority: "geoip", component: "dkim2/plugin.geoip.smtp_peer"},
			"dkim2/plugin.reputation.assessment": {provider: &countingFactProvider{}, source: decision.FactSourcePlugin, authority: "reputation", component: "dkim2/plugin.reputation.assessment"},
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newCheckpointRuntime() error = %v", err)
	}

	compiled, _ := catalog.Lookup(target)

	overrides := map[string]any{
		"resource.dkim2.verification_state":    verificationState,
		"resource.dkim2.authentication_state":  "PASS",
		"resource.dkim2.scope":                 "chain",
		"resource.dkim2.historical_content":    "complete",
		"resource.dkim2.historical_signatures": "complete",
		"resource.dkim2.custody_structure":     "not_present",
		"resource.dkim2.replay_class":          "first_seen",
		"resource.dkim2.local_policy_verdict":  "continue",
		"resource.dkim2.disposition":           "continue",
		"environment.rspamd.smtp_client_ip":    dkim2TestSMTPPeerIP,
	}
	for id, value := range factOverrides {
		overrides[id] = value
	}

	facts := dkim2ReferenceCallerFacts(t, compiled.Schema().Facts(), overrides)

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "dkim2-reference", Target: target,
		Options: decision.EvaluationOptions{IncludeDiagnostics: true},
	}, mustAuthorityCaller(t, false))
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	empty, _ := decision.NewFactSet(nil)
	checkpoint, _ := decision.NewCheckpoint(decision.CheckpointFinalDecision, empty)

	outcome, err := evaluator.Evaluate(context.Background(), checkpointEvaluation{
		request: request, checkpoint: checkpoint, facts: facts,
		supervisor: &recordingEffectAcceptor{}, generation: 1,
		finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	return outcome
}

// dkim2ReferencePolicyPath returns the Policy document under test: the
// override from dkim2PolicyFileEnv when set, otherwise the plugin's reference
// example as synced into the core tree.
func dkim2ReferencePolicyPath() string {
	if path := os.Getenv(dkim2PolicyFileEnv); path != "" {
		return filepath.Clean(path)
	}

	return filepath.Join("..", "..", "..", "..", "contrib", "plugins", "dkim2-intelligence", "examples", "policy_dkim2_rspamd_verifier.yml")
}

// compileDKIM2ReferenceCatalog compiles the operator-owned reference configuration.
func compileDKIM2ReferenceCatalog(t *testing.T) (*policyruntime.TargetCatalog, decision.Target) {
	t.Helper()

	path := dkim2ReferencePolicyPath()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(%s) error = %v", path, err)
	}

	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("Close(%s) error = %v", path, closeErr)
		}
	}()

	document, err := policyconfig.Decode("yaml", file)
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("configinput.Normalize() error = %v", err)
	}

	catalog, err := input.Compile(context.Background(), &recordingEffectAcceptor{})
	if err != nil {
		t.Fatalf("UnifiedPolicyInput.Compile() error = %v", err)
	}

	target, err := decision.NewTarget("dkim2", "accept-message-instance")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return catalog, target
}

// dkim2ReferenceCallerFacts constructs schema-valid caller facts for one verifier state.
func dkim2ReferenceCallerFacts(
	t *testing.T,
	schema []registry.FactSchema,
	stringOverrides map[string]any,
) decision.FactSet {
	t.Helper()

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "rspamd-verifier", "policy-test")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	facts := make([]decision.Fact, 0, len(schema))
	for _, definition := range schema {
		if !definition.Required() || !containsFactSource(definition.AllowedSources(), decision.FactSourceCaller) {
			continue
		}

		value := dkim2ReferenceFactValue(t, definition, stringOverrides)

		fact, factErr := decision.NewFact(definition.ID(), definition.Category(), value, provenance)
		if factErr != nil {
			t.Fatalf("NewFact(%s) error = %v", definition.ID(), factErr)
		}

		facts = append(facts, fact)
	}

	result, err := decision.NewFactSet(facts)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return result
}

// containsFactSource reports whether one schema source list contains the caller authority.
func containsFactSource(sources []decision.FactSource, source decision.FactSource) bool {
	for _, candidate := range sources {
		if candidate == source {
			return true
		}
	}

	return false
}

// dkim2ReferenceFactValue builds a smallest type-correct value for one fact schema.
func dkim2ReferenceFactValue(
	t *testing.T,
	definition registry.FactSchema,
	stringOverrides map[string]any,
) decision.Value {
	t.Helper()

	if value, exists := stringOverrides[definition.ID()]; exists {
		return dkim2PolicyValue(t, value)
	}

	if definition.Kind() == decision.ValueKindRecords {
		recordSchema, _ := definition.RecordSchema()

		return dkim2ReferenceRecordValue(t, recordSchema)
	}

	return dkim2ReferenceScalarValue(t, definition.Kind())
}

// dkim2ReferenceBooleanValue constructs one boolean fact value.
func dkim2ReferenceBooleanValue(t *testing.T, input bool) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{Boolean: &input})
	if err != nil {
		t.Fatalf("NewValue(boolean) error = %v", err)
	}

	return value
}

// schemaFactByID resolves one exact compiled schema fact.
func schemaFactByID(facts []registry.FactSchema, id string) (registry.FactSchema, bool) {
	for _, fact := range facts {
		if fact.ID() == id {
			return fact, true
		}
	}

	return registry.FactSchema{}, false
}

// dkim2ReferenceRecordValue builds one complete record from a closed schema.
func dkim2ReferenceRecordValue(t *testing.T, schema registry.RecordSchema) decision.Value {
	t.Helper()

	fields := make([]decision.RecordField, 0, len(schema.Fields()))
	for _, definition := range schema.Fields() {
		value := dkim2ReferenceScalarValue(t, definition.Kind())
		if definition.Name() == "signer_domain" {
			value = runtimeStringValue(t, dkim2TestSignerDomain)
		}

		fields = append(fields, dkim2ReferenceRecordField(t, definition.Name(), value))
	}

	return dkim2ReferenceRecordsValue(t, fields)
}

// dkim2ReferenceRecordField constructs one named immutable record field.
func dkim2ReferenceRecordField(t *testing.T, name string, value decision.Value) decision.RecordField {
	t.Helper()

	fieldValue, err := decision.NewRecordFieldValueFromValue(value)
	if err != nil {
		t.Fatalf("NewRecordFieldValueFromValue(%s) error = %v", name, err)
	}

	field, err := decision.NewRecordField(name, fieldValue)
	if err != nil {
		t.Fatalf("NewRecordField(%s) error = %v", name, err)
	}

	return field
}

// dkim2ReferenceRecordsValue wraps one complete field list as a single-record value.
func dkim2ReferenceRecordsValue(t *testing.T, fields []decision.RecordField) decision.Value {
	t.Helper()

	return dkim2ReferenceRecordListValue(t, []decision.Record{dkim2ReferenceRecord(t, fields)})
}

// dkim2ReferenceRecord constructs one immutable record.
func dkim2ReferenceRecord(t *testing.T, fields []decision.RecordField) decision.Record {
	t.Helper()

	record, err := decision.NewRecord(fields)
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}

	return record
}

// dkim2ReferenceRecordListValue wraps records as one immutable fact value.
func dkim2ReferenceRecordListValue(t *testing.T, input []decision.Record) decision.Value {
	t.Helper()

	records, err := decision.NewRecordList(input)
	if err != nil {
		t.Fatalf("NewRecordList() error = %v", err)
	}

	value, err := decision.NewValue(decision.ValueInput{Records: &records})
	if err != nil {
		t.Fatalf("NewValue(records) error = %v", err)
	}

	return value
}

// dkim2ReferenceScalarValue builds one constructed scalar or list value.
func dkim2ReferenceScalarValue(t *testing.T, kind decision.ValueKind) decision.Value {
	t.Helper()

	text := "x"
	boolean := false
	integer := int64(1)
	double := 1.0
	stringsValue := []string{}
	bytesValue := []byte{0}
	input := decision.ValueInput{}

	switch kind {
	case decision.ValueKindString:
		input.String = &text
	case decision.ValueKindBoolean:
		input.Boolean = &boolean
	case decision.ValueKindInteger:
		input.Integer = &integer
	case decision.ValueKindDouble:
		input.Double = &double
	case decision.ValueKindStrings:
		input.Strings = stringsValue
	case decision.ValueKindBytes:
		input.Bytes = bytesValue
	default:
		t.Fatalf("unsupported reference scalar kind %q", kind)
	}

	value, err := decision.NewValue(input)
	if err != nil {
		t.Fatalf("NewValue(%s) error = %v", kind, err)
	}

	return value
}

// dkim2PolicyCase describes deterministic provider and caller inputs and the expected ordered Policy outcome.
type dkim2PolicyCase struct {
	name, wantRule string
	hops           []map[string]any
	peer           map[string]any
	facts          map[string]any
	complete       *bool
	providerError  bool
	permit         bool
}

// dkim2CompositionOutputs supplies deterministic composed facts without asserting real upstream storage or cryptographic work.
func dkim2CompositionOutputs(t *testing.T, schema policyruntime.CompiledSchema, tc dkim2PolicyCase) []providedFact {
	t.Helper()

	result := []providedFact{}

	for _, name := range []string{"assessed_chain", "smtp_peer"} {
		id := "plugin.dkim2_intelligence." + name
		fact, _ := schemaFactByID(schema.Facts(), id)
		recordSchema, _ := fact.RecordSchema()

		count := 1
		if name == "assessed_chain" {
			count = 2
		}

		records := make([]decision.Record, 0, count)
		for i := 0; i < count; i++ {
			values := dkim2PolicyBaseline(name, i)

			var changes map[string]any
			if name == "smtp_peer" {
				changes = tc.peer
			} else if i < len(tc.hops) {
				changes = tc.hops[i]
			}

			for key, value := range changes {
				values[key] = value
			}

			normalizeDKIM2FixtureTuples(values)
			records = append(records, dkim2PolicyRecord(t, recordSchema, values))
		}

		result = append(result, providedFact{id: id, category: decision.FactCategoryResource, value: dkim2ReferenceRecordListValue(t, records)})
	}

	complete := true
	if tc.complete != nil {
		complete = *tc.complete
	}

	return append(result, providedFact{id: "plugin.dkim2_intelligence.assessment_complete", category: decision.FactCategoryResource, value: dkim2ReferenceBooleanValue(t, complete)})
}

// dkim2PolicyBaseline returns complete safe semantic fixture values for a historical hop, target or peer.
func dkim2PolicyBaseline(name string, index int) map[string]any {
	if name == "smtp_peer" {
		values := map[string]any{"reputation_profile": "operational", "geoip_state": "fresh", "geoip_age_seconds": int64(1), "target_contract_state": "matched", "target_contract_strength": "cidr"}
		for _, kind := range []string{"ip", "network", "asn"} {
			values[kind+"_state"] = "fresh"
			values[kind+"_band"] = "neutral"
			values[kind+"_override"] = "none"
			values[kind+"_confidence"] = .9
			values[kind+"_samples"] = 25.0
			values[kind+"_risk_score"] = 0.0
			values[kind+"_trust_score"] = .2
			values[kind+"_source_diversity"] = int64(1)
			values[kind+"_age_seconds"] = int64(1)
		}

		return values
	}

	values := map[string]any{"sequence": int64(index + 1), "message_instance": int64(index + 1), "hop_binding": make([]byte, 32), "is_target": index == 1, "signer_domain": "origin.example", "signature_state": "pass", "custody_transition": "origin", "recipe_mode": "unchanged", "recipe_body_mode": "absent", "history_header_state": "matched", "history_body_state": "matched", "body_availability": "known", "signer_reputation_state": "fresh", "signer_reputation_profile": "operational", "signer_reputation_band": "neutral", "signer_override": "none", "signer_risk_score": 0.0, "signer_trust_score": .2, "signer_confidence": .9, "signer_samples": 25.0, "signer_source_diversity": int64(1), "signer_reputation_age_seconds": int64(1), "change_count": int64(0), "affected_header_count": int64(0), "identity_contract_state": "domain_only", "identity_contract_strength": "domain_only"}
	if index == 1 {
		values["signer_domain"] = "google.example"
		values["custody_transition"] = "ordinary"
		values["identity_contract_state"] = "matched"
		values["identity_contract_strength"] = "cidr"
	}

	return values
}

// dkim2PolicyRecord supplies declared fields only, preserving the host's immutable schema and privacy checks.
func dkim2PolicyRecord(t *testing.T, schema registry.RecordSchema, values map[string]any) decision.Record {
	t.Helper()

	fields := []decision.RecordField{}

	for _, field := range schema.Fields() {
		if _, exists := values[field.Name()]; !exists && !field.Required() {
			continue
		}

		value := dkim2ReferenceScalarValue(t, field.Kind())
		if input, exists := values[field.Name()]; exists {
			value = dkim2PolicyValue(t, input)
		}

		fields = append(fields, dkim2ReferenceRecordField(t, field.Name(), value))
	}

	return dkim2ReferenceRecord(t, fields)
}

// dkim2PolicyValue converts explicit test inputs without integer-to-double inference.
func dkim2PolicyValue(t *testing.T, input any) decision.Value {
	t.Helper()

	value := decision.ValueInput{}

	switch x := input.(type) {
	case string:
		value.String = &x
	case bool:
		value.Boolean = &x
	case int64:
		value.Integer = &x
	case float64:
		value.Double = &x
	case []string:
		value.Strings = x
	case []byte:
		value.Bytes = x
	default:
		t.Fatalf("unsupported Policy fixture value %T", input)
	}

	result, err := decision.NewValue(value)
	if err != nil {
		t.Fatal(err)
	}

	return result
}

// normalizeDKIM2FixtureTuples removes conditional measurements for explicit absent or failed lookup states.
func normalizeDKIM2FixtureTuples(values map[string]any) {
	for _, kind := range []string{"ip", "network", "asn"} {
		state := values[kind+"_state"]
		if state != "not_found" && state != "unavailable" {
			continue
		}

		band := "unknown"
		if state == "unavailable" {
			band = "unavailable"
		}

		values[kind+"_band"] = band
		for _, suffix := range []string{"risk_score", "trust_score", "confidence", "samples", "source_diversity", "age_seconds"} {
			delete(values, kind+"_"+suffix)
		}
	}
}
