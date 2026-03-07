package oidc

import "testing"

func TestDefaultClaimMapper(t *testing.T) {
	claims := map[string]interface{}{
		"name":               "Alice Doe",
		"preferred_username": "alice",
		"email":              "alice@example.com",
	}

	name, username, email := DefaultClaimMapper(claims)
	if name != "Alice Doe" {
		t.Errorf("name: got %q, want %q", name, "Alice Doe")
	}
	if username != "alice" {
		t.Errorf("username: got %q, want %q", username, "alice")
	}
	if email != "alice@example.com" {
		t.Errorf("email: got %q, want %q", email, "alice@example.com")
	}
}

func TestDefaultClaimMapperMissingFields(t *testing.T) {
	// Simulate a provider that only sends email (no name, no preferred_username)
	claims := map[string]interface{}{
		"email": "bob@example.com",
	}

	name, username, email := DefaultClaimMapper(claims)
	if name != "" {
		t.Errorf("name: got %q, want empty", name)
	}
	if username != "" {
		t.Errorf("username: got %q, want empty", username)
	}
	if email != "bob@example.com" {
		t.Errorf("email: got %q, want %q", email, "bob@example.com")
	}
}

func TestDefaultClaimMapperEmptyMap(t *testing.T) {
	name, username, email := DefaultClaimMapper(map[string]interface{}{})
	if name != "" || username != "" || email != "" {
		t.Errorf("expected all empty, got name=%q username=%q email=%q", name, username, email)
	}
}

func TestDefaultClaimMapperNonStringValues(t *testing.T) {
	// Claims with non-string values should not panic, just return empty
	claims := map[string]interface{}{
		"name":               123,
		"preferred_username": true,
		"email":              []string{"bad"},
	}

	name, username, email := DefaultClaimMapper(claims)
	if name != "" || username != "" || email != "" {
		t.Errorf("expected all empty for non-string values, got name=%q username=%q email=%q", name, username, email)
	}
}

func TestGoogleClaimMapper(t *testing.T) {
	claims := map[string]interface{}{
		"name":        "Jane Doe",
		"email":       "jane.doe@gmail.com",
		"picture":     "https://lh3.googleusercontent.com/a/photo",
		"given_name":  "Jane",
		"family_name": "Doe",
	}

	name, username, email := GoogleClaimMapper(claims)
	if name != "Jane Doe" {
		t.Errorf("name: got %q, want %q", name, "Jane Doe")
	}
	if username != "jane.doe" {
		t.Errorf("username: got %q, want %q", username, "jane.doe")
	}
	if email != "jane.doe@gmail.com" {
		t.Errorf("email: got %q, want %q", email, "jane.doe@gmail.com")
	}
}

func TestGoogleClaimMapperNoEmail(t *testing.T) {
	claims := map[string]interface{}{
		"name": "Jane Doe",
	}

	name, username, email := GoogleClaimMapper(claims)
	if name != "Jane Doe" {
		t.Errorf("name: got %q, want %q", name, "Jane Doe")
	}
	if username != "" {
		t.Errorf("username: got %q, want empty", username)
	}
	if email != "" {
		t.Errorf("email: got %q, want empty", email)
	}
}

func TestGoogleClaimMapperEmptyMap(t *testing.T) {
	name, username, email := GoogleClaimMapper(map[string]interface{}{})
	if name != "" || username != "" || email != "" {
		t.Errorf("expected all empty, got name=%q username=%q email=%q", name, username, email)
	}
}

func TestGoogleClaimMapperEmailWithoutAt(t *testing.T) {
	// Edge case: email without @ (shouldn't happen, but should not panic)
	claims := map[string]interface{}{
		"email": "localpart",
	}

	_, username, _ := GoogleClaimMapper(claims)
	// No @ means no prefix extraction
	if username != "" {
		t.Errorf("username: got %q, want empty for email without @", username)
	}
}
