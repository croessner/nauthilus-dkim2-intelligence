// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package projection

import (
	"slices"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestVerifierProjectionAcceptsExactDraft07ReplayClasses pins the closed Draft-07 replay vocabulary.
func TestVerifierProjectionAcceptsExactDraft07ReplayClasses(t *testing.T) {
	want := []string{"not_checked", "not_eligible", "disabled", "first_seen", "exploded", "replayed", "indeterminate"}
	if !slices.Equal(replayClasses, want) {
		t.Fatalf("replayClasses = %v, want %v", replayClasses, want)
	}

	for _, class := range want {
		t.Run(class, func(t *testing.T) {
			request := replaceRequestStringFact(t, testDecisionRequest(t, "192.0.2.25"), "resource.dkim2.replay_class", class)
			if _, err := Decode(request); err != nil {
				t.Fatalf("Decode() error = %v for replay class %q", err, class)
			}
		})
	}
}

// TestVerifierProjectionRejectsUnknownReplayClass fails closed on replay classes outside Draft-07.
func TestVerifierProjectionRejectsUnknownReplayClass(t *testing.T) {
	for _, class := range []string{"eligible", "NOT_ELIGIBLE", ""} {
		request := replaceRequestStringFact(t, testDecisionRequest(t, "192.0.2.25"), "resource.dkim2.replay_class", class)
		if _, err := Decode(request); err == nil {
			t.Fatalf("Decode() accepted replay class %q", class)
		}
	}
}

func TestVerifierProjectionAcceptsExactRspamdScanActions(t *testing.T) {
	want := []string{
		"no action", "accept", "add header", "rewrite subject", "greylist",
		"soft reject", "reject", "quarantine", "discard",
	}
	if !slices.Equal(RspamdScanActions, want) {
		t.Fatalf("RspamdScanActions = %v, want exact adapter vocabulary %v", RspamdScanActions, want)
	}

	for _, action := range want {
		t.Run(action, func(t *testing.T) {
			request := replaceRequestStringFact(
				t, testDecisionRequest(t, "192.0.2.25"), FactScanAction, action,
			)
			if _, err := Decode(request); err != nil {
				t.Fatalf("Decode() error = %v for admitted action %q", err, action)
			}
		})
	}
}

func TestVerifierProjectionRejectsUnknownRspamdScanAction(t *testing.T) {
	request := replaceRequestStringFact(
		t, testDecisionRequest(t, "192.0.2.25"), FactScanAction, "ACCEPT",
	)
	if _, err := Decode(request); err == nil {
		t.Fatal("Decode() error = nil for unknown case-variant action")
	}
}

// replaceRequestStringFact rebuilds one immutable request with an exact string fact replacement.
func replaceRequestStringFact(
	t *testing.T,
	request pluginapi.DecisionFactRequest,
	id string,
	value string,
) pluginapi.DecisionFactRequest {
	t.Helper()

	return replaceRequestFact(t, request, id, testStringValue(t, value))
}
