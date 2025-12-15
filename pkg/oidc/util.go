package oidc

import (
	"encoding/base64"
	"errors"

	"github.com/gorilla/securecookie"
)

func generateSessionState() (string, error) {
	return getRandomString(32)
}

func getRandomString(n int) (string, error) {
	bytes := securecookie.GenerateRandomKey(n)
	if bytes == nil {
		return "", errors.New("failed to generate random key")
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func mergeScopes(defaultScopes, additionalScopes []string) []string {
	scopeMap := make(map[string]bool)
	for _, scope := range defaultScopes {
		scopeMap[scope] = true
	}
	for _, scope := range additionalScopes {
		scopeMap[scope] = true
	}
	mergedScopes := make([]string, 0, len(scopeMap))
	for scope := range scopeMap {
		mergedScopes = append(mergedScopes, scope)
	}
	return mergedScopes
}
