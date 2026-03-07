package oidc

import "strings"

// mapClaims delegates to the configured ClaimMapper or falls back to DefaultClaimMapper.
func (h *Handler) mapClaims(claims map[string]interface{}) (name, username, email string) {
	if h.Options.Provider.ClaimMapper != nil {
		return h.Options.Provider.ClaimMapper(claims)
	}
	return DefaultClaimMapper(claims)
}

// DefaultClaimMapper extracts claims using standard OIDC claim names.
// Reads "name", "preferred_username", and "email" with safe type assertions.
// Works with Keycloak, Auth0, and most standard OIDC providers.
func DefaultClaimMapper(claims map[string]interface{}) (name, username, email string) {
	if v, ok := claims["name"].(string); ok {
		name = v
	}
	if v, ok := claims["preferred_username"].(string); ok {
		username = v
	}
	if v, ok := claims["email"].(string); ok {
		email = v
	}
	return
}

// GoogleClaimMapper extracts claims from Google's ID token.
// Google provides: name, email, picture, given_name, family_name
// Google does NOT provide: preferred_username
// Username falls back to the email prefix (the part before @).
func GoogleClaimMapper(claims map[string]interface{}) (name, username, email string) {
	if v, ok := claims["name"].(string); ok {
		name = v
	}
	if v, ok := claims["email"].(string); ok {
		email = v
		if at := strings.Index(email, "@"); at > 0 {
			username = email[:at]
		}
	}
	return
}
