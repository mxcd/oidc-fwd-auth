package oidc

import (
	"sort"
	"testing"
)

func TestGenerateSessionState(t *testing.T) {
	state, err := generateSessionState()
	if err != nil {
		t.Fatalf("generateSessionState failed: %v", err)
	}
	if state == "" {
		t.Error("expected non-empty state")
	}
}

func TestGenerateSessionStateUniqueness(t *testing.T) {
	states := make(map[string]bool)
	for range 100 {
		state, err := generateSessionState()
		if err != nil {
			t.Fatalf("generateSessionState failed: %v", err)
		}
		if states[state] {
			t.Fatalf("duplicate state generated: %s", state)
		}
		states[state] = true
	}
}

func TestMergeScopesNoDuplicates(t *testing.T) {
	result := mergeScopes(
		[]string{"openid", "profile", "email"},
		[]string{"groups", "roles"},
	)
	sort.Strings(result)
	expected := []string{"email", "groups", "openid", "profile", "roles"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d scopes, got %d: %v", len(expected), len(result), result)
	}
	for i, s := range expected {
		if result[i] != s {
			t.Errorf("scope[%d]: got %q, want %q", i, result[i], s)
		}
	}
}

func TestMergeScopesWithOverlap(t *testing.T) {
	result := mergeScopes(
		[]string{"openid", "profile", "email"},
		[]string{"email", "groups"},
	)
	if len(result) != 4 {
		t.Errorf("expected 4 scopes (no duplicates), got %d: %v", len(result), result)
	}
}

func TestMergeScopesEmptyAdditional(t *testing.T) {
	result := mergeScopes([]string{"openid", "profile"}, nil)
	if len(result) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(result))
	}
}

func TestMergeScopesBothEmpty(t *testing.T) {
	result := mergeScopes(nil, nil)
	if len(result) != 0 {
		t.Errorf("expected 0 scopes, got %d", len(result))
	}
}
