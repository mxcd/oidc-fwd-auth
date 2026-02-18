package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestSessionStore(t *testing.T) *SessionStore {
	t.Helper()
	store, err := newSessionStore(&SessionOptions{
		SecretSigningKey:    "signing-key-at-least-32-bytes!!!", // 32 bytes
		SecretEncryptionKey: "01234567890123456789012345678901", // 32 bytes
		Name:                "test-session",
		MaxAge:              3600,
	})
	if err != nil {
		t.Fatalf("failed to create session store: %v", err)
	}
	return store
}

// applyCookies copies Set-Cookie headers from a response to a new request
func applyCookies(resp *httptest.ResponseRecorder, req *http.Request) {
	for _, cookie := range resp.Result().Cookies() {
		req.AddCookie(cookie)
	}
}

// newRequestWithCookies creates a new GET request carrying cookies from a previous response
func newRequestWithCookies(resp *httptest.ResponseRecorder) *http.Request {
	req := httptest.NewRequest("GET", "/", nil)
	applyCookies(resp, req)
	return req
}

func TestNewSession(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	err := store.NewSession(req, w)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Should have a Set-Cookie header
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected Set-Cookie header")
	}

	found := false
	for _, c := range cookies {
		if c.Name == "test-session" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected cookie named 'test-session'")
	}
}

func TestSetAndGetStringValue(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	err := store.NewSession(req, w)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Build request with session cookie
	req2 := newRequestWithCookies(w)
	w2 := httptest.NewRecorder()

	err = store.SetStringValue(req2, w2, "state", "test-state-value")
	if err != nil {
		t.Fatalf("SetStringValue failed: %v", err)
	}

	// Read it back
	req3 := newRequestWithCookies(w)
	// Also apply any new cookies from w2
	applyCookies(w2, req3)

	val, err := store.GetStringValue(req3, "state")
	if err != nil {
		t.Fatalf("GetStringValue failed: %v", err)
	}
	if val != "test-state-value" {
		t.Errorf("expected 'test-state-value', got %q", val)
	}
}

func TestGetStringValueNoSession(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)

	val, err := store.GetStringValue(req, "state")
	if err != nil {
		t.Fatalf("GetStringValue failed: %v", err)
	}
	if val != "" {
		t.Errorf("expected empty string, got %q", val)
	}
}

func TestSetAndGetSessionData(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	err := store.NewSession(req, w)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	data := &SessionData{
		Authenticated: true,
		Sub:           "user-123",
		Name:          "Test User",
		Username:      "testuser",
		Email:         "test@example.com",
		Claims: map[string]interface{}{
			"role":  "admin",
			"group": "engineering",
		},
	}

	req2 := newRequestWithCookies(w)
	w2 := httptest.NewRecorder()

	err = store.SetSessionData(req2, w2, data)
	if err != nil {
		t.Fatalf("SetSessionData failed: %v", err)
	}

	// Read it back
	req3 := newRequestWithCookies(w)
	applyCookies(w2, req3)

	got, err := store.GetSessionData(req3)
	if err != nil {
		t.Fatalf("GetSessionData failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected session data, got nil")
	}
	if !got.Authenticated {
		t.Error("expected Authenticated=true")
	}
	if got.Sub != "user-123" {
		t.Errorf("Sub: got %q, want %q", got.Sub, "user-123")
	}
	if got.Name != "Test User" {
		t.Errorf("Name: got %q, want %q", got.Name, "Test User")
	}
	if got.Username != "testuser" {
		t.Errorf("Username: got %q, want %q", got.Username, "testuser")
	}
	if got.Email != "test@example.com" {
		t.Errorf("Email: got %q, want %q", got.Email, "test@example.com")
	}
	if got.Claims["role"] != "admin" {
		t.Errorf("Claims[role]: got %v", got.Claims["role"])
	}
}

func TestGetSessionDataNoSession(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)

	data, err := store.GetSessionData(req)
	if err != nil {
		t.Fatalf("GetSessionData failed: %v", err)
	}
	if data != nil {
		t.Error("expected nil data for no session")
	}
}

func TestSetAndGetStringFlash(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	err := store.NewSession(req, w)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	req2 := newRequestWithCookies(w)
	w2 := httptest.NewRecorder()

	err = store.SetStringFlash(req2, w2, "/original-page")
	if err != nil {
		t.Fatalf("SetStringFlash failed: %v", err)
	}

	// Get flash (should consume it)
	req3 := newRequestWithCookies(w)
	applyCookies(w2, req3)
	w3 := httptest.NewRecorder()

	flash, err := store.GetStringFlash(req3, w3)
	if err != nil {
		t.Fatalf("GetStringFlash failed: %v", err)
	}
	if flash == nil {
		t.Fatal("expected flash message, got nil")
	}
	if *flash != "/original-page" {
		t.Errorf("flash: got %q, want %q", *flash, "/original-page")
	}

	// Second get should return nil (consumed)
	req4 := newRequestWithCookies(w)
	applyCookies(w3, req4)
	w4 := httptest.NewRecorder()

	flash2, err := store.GetStringFlash(req4, w4)
	if err != nil {
		t.Fatalf("second GetStringFlash failed: %v", err)
	}
	if flash2 != nil {
		t.Errorf("expected nil flash after consumption, got %q", *flash2)
	}
}

func TestGetStringFlashNoSession(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	flash, err := store.GetStringFlash(req, w)
	if err != nil {
		t.Fatalf("GetStringFlash failed: %v", err)
	}
	if flash != nil {
		t.Error("expected nil flash for no session")
	}
}

func TestMultipleFlashes(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	err := store.NewSession(req, w)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Set two flashes
	req2 := newRequestWithCookies(w)
	w2 := httptest.NewRecorder()
	err = store.SetStringFlash(req2, w2, "first")
	if err != nil {
		t.Fatalf("first SetStringFlash failed: %v", err)
	}

	req3 := newRequestWithCookies(w)
	applyCookies(w2, req3)
	w3 := httptest.NewRecorder()
	err = store.SetStringFlash(req3, w3, "second")
	if err != nil {
		t.Fatalf("second SetStringFlash failed: %v", err)
	}

	// Get first flash
	req4 := newRequestWithCookies(w)
	applyCookies(w3, req4)
	w4 := httptest.NewRecorder()
	flash1, err := store.GetStringFlash(req4, w4)
	if err != nil {
		t.Fatalf("first GetStringFlash failed: %v", err)
	}
	if flash1 == nil || *flash1 != "first" {
		t.Errorf("expected 'first', got %v", flash1)
	}

	// Get second flash
	req5 := newRequestWithCookies(w)
	applyCookies(w4, req5)
	w5 := httptest.NewRecorder()
	flash2, err := store.GetStringFlash(req5, w5)
	if err != nil {
		t.Fatalf("second GetStringFlash failed: %v", err)
	}
	if flash2 == nil || *flash2 != "second" {
		t.Errorf("expected 'second', got %v", flash2)
	}
}

func TestDelete(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	err := store.NewSession(req, w)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Set some data
	req2 := newRequestWithCookies(w)
	w2 := httptest.NewRecorder()
	err = store.SetSessionData(req2, w2, &SessionData{
		Authenticated: true,
		Sub:           "user-to-delete",
	})
	if err != nil {
		t.Fatalf("SetSessionData failed: %v", err)
	}

	// Delete
	req3 := newRequestWithCookies(w)
	applyCookies(w2, req3)
	w3 := httptest.NewRecorder()
	err = store.Delete(req3, w3)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Cookie should be expired (MaxAge < 0)
	for _, c := range w3.Result().Cookies() {
		if c.Name == "test-session" && c.MaxAge >= 0 {
			t.Error("expected cookie to be expired after Delete")
		}
	}

	// Session data should be gone
	req4 := newRequestWithCookies(w3)
	data, err := store.GetSessionData(req4)
	if err != nil {
		t.Fatalf("GetSessionData after delete failed: %v", err)
	}
	if data != nil {
		t.Error("expected nil data after delete")
	}
}

func TestDeleteNoSession(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Should not error even with no session
	err := store.Delete(req, w)
	if err != nil {
		t.Fatalf("Delete with no session failed: %v", err)
	}
}

func TestSessionDataAndStringValuesCoexist(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	err := store.NewSession(req, w)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Set string value
	req2 := newRequestWithCookies(w)
	w2 := httptest.NewRecorder()
	err = store.SetStringValue(req2, w2, "state", "some-state")
	if err != nil {
		t.Fatalf("SetStringValue failed: %v", err)
	}

	// Set session data (should not overwrite string values)
	req3 := newRequestWithCookies(w)
	applyCookies(w2, req3)
	w3 := httptest.NewRecorder()
	err = store.SetSessionData(req3, w3, &SessionData{
		Authenticated: true,
		Sub:           "user-789",
	})
	if err != nil {
		t.Fatalf("SetSessionData failed: %v", err)
	}

	// Verify both exist
	req4 := newRequestWithCookies(w)
	applyCookies(w3, req4)

	val, err := store.GetStringValue(req4, "state")
	if err != nil {
		t.Fatalf("GetStringValue failed: %v", err)
	}
	if val != "some-state" {
		t.Errorf("state: got %q, want %q", val, "some-state")
	}

	data, err := store.GetSessionData(req4)
	if err != nil {
		t.Fatalf("GetSessionData failed: %v", err)
	}
	if data == nil || data.Sub != "user-789" {
		t.Error("session data missing or wrong after setting string value")
	}
}

func TestCookieSizeIsSmall(t *testing.T) {
	store := newTestSessionStore(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	err := store.NewSession(req, w)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Store a large session data (would exceed 4KB in cookie-based store)
	claims := make(map[string]interface{})
	for i := 0; i < 50; i++ {
		key := string(rune('a'+i%26)) + string(rune('0'+i/26))
		claims[key] = "a]very-long-value-that-would-normally-blow-up-cookie-size-limits-if-stored-directly"
	}

	req2 := newRequestWithCookies(w)
	w2 := httptest.NewRecorder()
	err = store.SetSessionData(req2, w2, &SessionData{
		Authenticated: true,
		Sub:           "user-with-many-claims",
		Name:          "Large Claims User",
		Username:      "largeclaimsuser",
		Email:         "large@example.com",
		Claims:        claims,
	})
	if err != nil {
		t.Fatalf("SetSessionData failed: %v", err)
	}

	// The cookie should be small (only contains session ID, not the data)
	for _, c := range w2.Result().Cookies() {
		if c.Name == "test-session" {
			// gorilla securecookie encoded value. With just a UUID session ID
			// this should be well under 4KB. Previously this would have been >4KB.
			if len(c.Value) > 1024 {
				t.Errorf("cookie too large (%d bytes); session data should be server-side", len(c.Value))
			}
			return
		}
	}
}

func TestNewSessionStoreDefaults(t *testing.T) {
	store, err := newSessionStore(&SessionOptions{
		SecretSigningKey:    "signing-key-at-least-32-bytes!!!",
		SecretEncryptionKey: "01234567890123456789012345678901",
		Name:                "test",
		MaxAge:              7200,
	})
	if err != nil {
		t.Fatalf("newSessionStore failed: %v", err)
	}

	if store.Options.CacheSize != 10000 {
		t.Errorf("CacheSize: got %d, want 10000", store.Options.CacheSize)
	}
	if store.Options.CacheTTL.Seconds() != 7200 {
		t.Errorf("CacheTTL: got %v, want 7200s", store.Options.CacheTTL)
	}
}

func TestApplyRedisDefaults(t *testing.T) {
	r := &RedisSessionOptions{
		Host: "redis-host",
	}
	applyRedisDefaults(r)

	if r.Port != 6379 {
		t.Errorf("Port: got %d, want 6379", r.Port)
	}
	if r.KeyPrefix != "oidc-sessions" {
		t.Errorf("KeyPrefix: got %q, want %q", r.KeyPrefix, "oidc-sessions")
	}
	if r.PubSubChannelName != "oidc-session-events" {
		t.Errorf("PubSubChannelName: got %q, want %q", r.PubSubChannelName, "oidc-session-events")
	}
}

func TestApplyRedisDefaultsPreservesExisting(t *testing.T) {
	r := &RedisSessionOptions{
		Host:              "redis-host",
		Port:              6380,
		KeyPrefix:         "custom-prefix",
		PubSubChannelName: "custom-channel",
	}
	applyRedisDefaults(r)

	if r.Port != 6380 {
		t.Errorf("Port should not be overwritten: got %d", r.Port)
	}
	if r.KeyPrefix != "custom-prefix" {
		t.Errorf("KeyPrefix should not be overwritten: got %q", r.KeyPrefix)
	}
	if r.PubSubChannelName != "custom-channel" {
		t.Errorf("PubSubChannelName should not be overwritten: got %q", r.PubSubChannelName)
	}
}
