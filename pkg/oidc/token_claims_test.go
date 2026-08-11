package oidc

import (
	"reflect"
	"testing"
)

// claims arrive from encoding/json, so every array is []interface{} whatever
// the element type — these tests use that shape on purpose.
func TestClaimExtraction(t *testing.T) {
	const clientID = "statics-scoring"

	for _, tc := range []struct {
		name        string
		claims      map[string]interface{}
		realmRoles  []string
		clientRoles []string
		groups      []string
	}{
		{
			name: "keycloak's usual shape",
			claims: map[string]interface{}{
				"realm_access":    map[string]interface{}{"roles": []interface{}{"admin", "offline_access"}},
				"resource_access": map[string]interface{}{clientID: map[string]interface{}{"roles": []interface{}{"scoring-admin"}}},
				"groups":          []interface{}{"/statics-scoring/admins"},
			},
			realmRoles:  []string{"admin", "offline_access"},
			clientRoles: []string{"scoring-admin"},
			groups:      []string{"/statics-scoring/admins"},
		},
		{
			name: "roles of another client are not ours",
			claims: map[string]interface{}{
				"resource_access": map[string]interface{}{"other-app": map[string]interface{}{"roles": []interface{}{"admin"}}},
			},
		},
		{
			name: "non-string entries are skipped, not fatal",
			claims: map[string]interface{}{
				"realm_access": map[string]interface{}{"roles": []interface{}{42, "admin", nil}},
			},
			realmRoles: []string{"admin"},
		},
		{
			name:   "a token with none of the structures",
			claims: map[string]interface{}{"sub": "abc"},
		},
		{
			name:   "no claims at all",
			claims: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := realmRolesFromClaims(tc.claims); !reflect.DeepEqual(got, tc.realmRoles) {
				t.Errorf("realm roles: got %v, want %v", got, tc.realmRoles)
			}
			if got := clientRolesFromClaims(tc.claims, clientID); !reflect.DeepEqual(got, tc.clientRoles) {
				t.Errorf("client roles: got %v, want %v", got, tc.clientRoles)
			}
			if got := groupsFromClaims(tc.claims); !reflect.DeepEqual(got, tc.groups) {
				t.Errorf("groups: got %v, want %v", got, tc.groups)
			}
		})
	}
}

// An empty client ID must not make every client's roles ours.
func TestClientRolesWithoutAClientID(t *testing.T) {
	claims := map[string]interface{}{
		"resource_access": map[string]interface{}{"some-app": map[string]interface{}{"roles": []interface{}{"admin"}}},
	}
	if got := clientRolesFromClaims(claims, ""); got != nil {
		t.Errorf("expected no client roles without a client ID, got %v", got)
	}
}
