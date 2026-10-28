// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//go:build dkim2policyharness

package service

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

// TestDKIM2CorrelatedPolicyScenarios evaluates the real compiled scheduler and canonical ordered Policy with deterministic provider facts.
func TestDKIM2CorrelatedPolicyScenarios(t *testing.T) {
	catalog, target := compileDKIM2ReferenceCatalog(t)
	compiled, _ := catalog.Lookup(target)

	for _, tc := range dkim2PolicyCases() {
		t.Run(tc.name, func(t *testing.T) {
			outputs := dkim2CompositionOutputs(t, compiled.Schema(), tc)
			assertDKIM2ReferenceProviderFacts(t, compiled.Schema(), outputs)

			provider := &countingFactProvider{facts: outputs}
			if tc.providerError {
				provider.err = errors.New("deterministic unavailable provider")
			}

			outcome := evaluateDKIM2Reference(t, catalog, target, provider, "PASS", tc.facts)

			expected := decision.EffectDeny
			if tc.permit {
				expected = decision.EffectPermit
			}

			if tc.providerError {
				expected = decision.EffectIndeterminate
			}

			if outcome.response.Effect() != expected || outcome.response.Policy().Rule() != tc.wantRule {
				t.Fatalf("got %s/%s (%s), want %s/%s", outcome.response.Effect(), outcome.response.Policy().Rule(), outcome.response.Status().Code(), expected, tc.wantRule)
			}

			if tc.providerError && !outcome.response.Status().Retryable() {
				t.Fatal("required provider outage is not retryable")
			}

			assertDKIM2DiagnosticsDoNotLeak(t, outcome.response)
		})
	}
}

// dkim2PolicyCases fixes positive, same-hop, current-target, availability and invariant precedence vectors
// for the Draft-08 verifier contract, including the non-replay not_eligible class and coherent Draft-08
// Section 14.1 verification and replay authentication results.
func dkim2PolicyCases() []dkim2PolicyCase {
	no := false

	result := []dkim2PolicyCase{
		{name: "named current provider", permit: true, wantRule: "permit_selected_provider_header_relay"},
		{name: "bad reputation and body same hop", hops: []map[string]any{{"signer_reputation_band": "suspicious", "change_classes": []string{"body.rewrite"}}}, wantRule: "deny_bad_reputation_body_change"},
		{name: "bad reputation and body split across hops", hops: []map[string]any{{"signer_reputation_band": "suspicious"}, {"change_classes": []string{"body.rewrite"}}}},
		{name: "header only signer body without header", hops: []map[string]any{{"signer_domain": "relay.example", "change_classes": []string{"body.rewrite"}}}, wantRule: "deny_body_change_for_header_only_signer"},
		{name: "header only signer header permitted", hops: []map[string]any{{"signer_domain": "relay.example", "change_classes": []string{"header.rewrite"}}}, permit: true, wantRule: "permit_selected_provider_header_relay"},
		{name: "named provider historical only", hops: []map[string]any{{"signer_domain": "google.example"}, {"signer_domain": "other.example"}}},
		{name: "historical identity cannot be current", hops: []map[string]any{nil, {"identity_contract_state": "domain_only", "identity_contract_strength": "domain_only"}}, wantRule: "deny_target_identity"},
		{name: "named provider ASN identity distinct", hops: []map[string]any{nil, {"identity_contract_strength": "asn"}}, permit: true, wantRule: "permit_selected_provider_header_relay"},
		{name: "current score and prior IP below direct confidence gate", peer: map[string]any{"ip_band": "suspicious", "ip_confidence": .2}, facts: map[string]any{"environment.rspamd.metric_score": 8.0}, wantRule: "deny_rspamd_risk_on_known_bad_ingress"},
		{name: "current score alone never invents bad prior state", facts: map[string]any{"environment.rspamd.metric_score": 8.0}, permit: true, wantRule: "permit_selected_provider_header_relay"},
		{name: "incomplete correlation", complete: &no, wantRule: "deny_incomplete_assessment"},
		{name: "upper case signature cannot permit", hops: []map[string]any{{"signature_state": "PASS"}}, wantRule: "deny_signature_state"},
		{name: "required provider fails", providerError: true},
		{name: "historical signer stale", hops: []map[string]any{{"signer_reputation_state": "stale"}}, wantRule: "deny_unusable_reputation"},
		{name: "originator-only replay class is not a replay", facts: map[string]any{"resource.dkim2.replay_class": "not_eligible"}, permit: true, wantRule: "permit_selected_provider_header_relay"},
		{name: "exploded replay class is not a replay", facts: map[string]any{"resource.dkim2.replay_class": "exploded"}, permit: true, wantRule: "permit_selected_provider_header_relay"},
		{name: "current geography unavailable", peer: map[string]any{"geoip_state": "unavailable"}, wantRule: "deny_unusable_reputation"},
	}
	for _, kind := range []string{"ip", "network", "asn"} {
		result = append(result, dkim2PolicyCase{name: "independent " + kind + " risk", peer: map[string]any{kind + "_band": "suspicious", kind + "_samples": 25.0}, wantRule: "deny_bad_smtp_peer_" + kind + "_reputation"})
		for _, state := range []string{"stale", "not_found", "unavailable"} {
			result = append(result, dkim2PolicyCase{name: kind + " " + state, peer: map[string]any{kind + "_state": state}, wantRule: "deny_unusable_reputation"})
		}
	}

	for _, violation := range []string{"authentication_not_pass", "body_unavailable", "history_not_matched", "upstream_nonpermittable"} {
		result = append(result, dkim2PolicyCase{name: "hard " + violation, hops: []map[string]any{{"violation_classes": []string{violation}}}, wantRule: "deny_integrity_violation"})
	}

	for _, tc := range []struct{ fact, value, rule string }{{"verification_state", "FAIL", "deny_nonpass_verifier_state"}, {"authentication_state", "FAIL", "deny_nonpass_authentication"}, {"replay_class", "replayed", "deny_replay"}, {"custody_structure", "terminal_nd_requires_oob", "deny_terminal_nd"}, {"local_policy_verdict", "reject", "deny_noncontinuable_local_verdict"}, {"disposition", "reject", "deny_noncontinuable_disposition"}} {
		result = append(result, dkim2PolicyCase{name: tc.rule, facts: map[string]any{"resource.dkim2." + tc.fact: tc.value}, wantRule: tc.rule})
	}

	result = append(result, dkim2Draft08ResultCases()...)

	return result
}

// dkim2Draft08ResultCases pairs each Draft-08 state with a reason the producer reports for it.
// Verification failures carry the same authentication result and an unchecked replay class;
// replay failures keep a PASS verification. Every non-PASS result must be denied.
func dkim2Draft08ResultCases() []dkim2PolicyCase {
	result := []dkim2PolicyCase{}

	for _, tc := range []struct{ state, reason string }{
		{"FAIL", "custody_mismatch"}, {"FAIL", "body_history_unavailable"}, {"FAIL", "from_not_authentic"},
		{"FAIL", "timestamp_invalid"}, {"FAIL", "out_of_band_required"}, {"PERMERROR", "invalid_recipe"},
		{"TEMPERROR", "provider_temporary"},
	} {
		result = append(result, dkim2PolicyCase{
			name: "Draft-08 verification " + tc.state + " " + tc.reason,
			facts: map[string]any{
				"resource.dkim2.verification_state": tc.state, "resource.dkim2.verification_reason": tc.reason,
				"resource.dkim2.authentication_state": tc.state, "resource.dkim2.authentication_reason": tc.reason,
				"resource.dkim2.replay_class": "not_checked",
			},
			wantRule: "deny_nonpass_verifier_state",
		})
	}

	for _, tc := range []struct{ replay, state, reason string }{
		{"replayed", "FAIL", "duplicate_message_without_exploded"},
		{"indeterminate", "TEMPERROR", "replay_indeterminate"},
		{"indeterminate", "TEMPERROR", "replay_evidence_unavailable"},
	} {
		result = append(result, dkim2PolicyCase{
			name: "Draft-08 replay " + tc.replay + " " + tc.reason,
			facts: map[string]any{
				"resource.dkim2.replay_class": tc.replay, "resource.dkim2.authentication_state": tc.state,
				"resource.dkim2.authentication_reason": tc.reason,
			},
			wantRule: "deny_nonpass_authentication",
		})
	}

	return result
}
