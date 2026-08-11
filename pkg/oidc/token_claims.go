package oidc

import (
	"context"
	"fmt"
)

// Keycloak puts authorization data — realm_access, resource_access, groups —
// in the ACCESS token by default. The ID token carries it only if someone turns
// on "Add to ID token" for each individual mapper, which is off out of the box.
// A consumer reading roles off the ID token therefore sees nothing and denies
// everyone, with no error anywhere to point at.
//
// So the access token is read first and the ID token second, and both are only
// consulted when the Admin API (gocloak) is not configured — that one is
// authoritative because it resolves composite roles the tokens may not carry.

// parseAccessTokenClaims verifies the access token against the provider's keys
// and returns its claims. The audience check is skipped on purpose: an access
// token is audienced at the resource server it is meant for, not at this
// client, so the ID token verifier would reject every one of them.
//
// Not every provider issues a JWT here — Google's access token is opaque — so
// callers treat an error as "no claims available", never as a failed login.
func (h *Handler) parseAccessTokenClaims(ctx context.Context, rawAccessToken string) (map[string]interface{}, error) {
	if rawAccessToken == "" {
		return nil, fmt.Errorf("no access token in the token response")
	}
	if h.AccessTokenVerifier == nil {
		return nil, fmt.Errorf("no access token verifier configured")
	}

	token, err := h.AccessTokenVerifier.Verify(ctx, rawAccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify access token: %w", err)
	}

	var claims map[string]interface{}
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse access token claims: %w", err)
	}
	return claims, nil
}

// realmRolesFromClaims reads keycloak's realm_access.roles.
func realmRolesFromClaims(claims map[string]interface{}) []string {
	realmAccess, _ := claims["realm_access"].(map[string]interface{})
	return stringsFromClaim(realmAccess["roles"])
}

// clientRolesFromClaims reads keycloak's resource_access.<clientID>.roles.
func clientRolesFromClaims(claims map[string]interface{}, clientID string) []string {
	if clientID == "" {
		return nil
	}
	resourceAccess, _ := claims["resource_access"].(map[string]interface{})
	client, _ := resourceAccess[clientID].(map[string]interface{})
	return stringsFromClaim(client["roles"])
}

// groupsFromClaims reads the group membership claim. Whether the entries carry
// the full path ("/parent/child") or the bare name is a mapper setting, so
// consumers must tolerate both.
func groupsFromClaims(claims map[string]interface{}) []string {
	return stringsFromClaim(claims["groups"])
}

// stringsFromClaim reads a JSON array of strings out of decoded claims, which
// arrive as []interface{} whatever the element type.
func stringsFromClaim(value interface{}) []string {
	raw, ok := value.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// applyTokenAuthorization fills RealmRoles, ClientRoles and Groups from the
// tokens, preferring the access token and falling back to the ID token.
func (h *Handler) applyTokenAuthorization(sessionData *SessionData, idTokenClaims map[string]interface{}) {
	clientID := h.Options.Provider.ClientId

	sessionData.RealmRoles = firstNonEmpty(
		realmRolesFromClaims(sessionData.AccessTokenClaims),
		realmRolesFromClaims(idTokenClaims))
	sessionData.ClientRoles = firstNonEmpty(
		clientRolesFromClaims(sessionData.AccessTokenClaims, clientID),
		clientRolesFromClaims(idTokenClaims, clientID))
	sessionData.Groups = firstNonEmpty(
		groupsFromClaims(sessionData.AccessTokenClaims),
		groupsFromClaims(idTokenClaims))
}

func firstNonEmpty(values ...[]string) []string {
	for _, value := range values {
		if len(value) > 0 {
			return value
		}
	}
	return nil
}
