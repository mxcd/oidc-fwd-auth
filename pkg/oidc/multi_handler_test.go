package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
)

func newTestMultiHandler(t *testing.T, sessionOpts *SessionOptions, multiOpts *MultiHandlerOptions) *MultiHandler {
	t.Helper()
	if multiOpts == nil {
		multiOpts = &MultiHandlerOptions{
			Session: sessionOpts,
		}
	}
	if multiOpts.Session == nil {
		multiOpts.Session = sessionOpts
	}
	mh, err := NewMultiHandler(multiOpts)
	if err != nil {
		t.Fatalf("NewMultiHandler: %v", err)
	}
	return mh
}

func defaultTestSessionOpts() *SessionOptions {
	return &SessionOptions{
		SecretSigningKey:    testSessionSigningKey,
		SecretEncryptionKey: testSessionEncryptionKey,
		Name:                "multi-test-session",
		MaxAge:              3600,
	}
}

func TestNewMultiHandlerNilOptions(t *testing.T) {
	_, err := NewMultiHandler(nil)
	if err == nil {
		t.Fatal("expected error for nil options")
	}
}

func TestNewMultiHandlerNilSession(t *testing.T) {
	_, err := NewMultiHandler(&MultiHandlerOptions{})
	if err == nil {
		t.Fatal("expected error for nil session options")
	}
}

func TestNewMultiHandlerSuccess(t *testing.T) {
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)
	if mh.SessionStore == nil {
		t.Fatal("expected non-nil SessionStore")
	}
	if len(mh.Handlers) != 0 {
		t.Errorf("expected 0 handlers, got %d", len(mh.Handlers))
	}
}

func TestAddProviderSuccess(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)

	err := mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name:         "test-provider",
			Issuer:       provider.URL,
			ClientId:     testClientID,
			ClientSecret: testClientSecret,
			RedirectUri:  "http://localhost:8080/auth/test-provider/callback",
		},
		AuthBaseContextPath: "/auth/test-provider",
	})
	if err != nil {
		t.Fatalf("AddProvider: %v", err)
	}

	if len(mh.Handlers) != 1 {
		t.Errorf("expected 1 handler, got %d", len(mh.Handlers))
	}
	if _, ok := mh.Handlers["test-provider"]; !ok {
		t.Error("expected handler with key 'test-provider'")
	}
}

func TestAddProviderDefaultName(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)

	err := mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Issuer:       provider.URL,
			ClientId:     testClientID,
			ClientSecret: testClientSecret,
			RedirectUri:  "http://localhost:8080/auth/oidc/callback",
		},
	})
	if err != nil {
		t.Fatalf("AddProvider: %v", err)
	}

	if _, ok := mh.Handlers["oidc"]; !ok {
		t.Error("expected handler with key 'oidc' (default name)")
	}
}

func TestAddProviderDuplicate(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)

	opts := &Options{
		Provider: &ProviderOptions{
			Name:         "dup",
			Issuer:       provider.URL,
			ClientId:     testClientID,
			ClientSecret: testClientSecret,
			RedirectUri:  "http://localhost:8080/auth/dup/callback",
		},
		AuthBaseContextPath: "/auth/dup",
	}

	if err := mh.AddProvider(opts); err != nil {
		t.Fatalf("first AddProvider: %v", err)
	}

	// Need a fresh opts since the first call modifies ExternalSessionStore
	opts2 := &Options{
		Provider: &ProviderOptions{
			Name:         "dup",
			Issuer:       provider.URL,
			ClientId:     testClientID,
			ClientSecret: testClientSecret,
			RedirectUri:  "http://localhost:8080/auth/dup/callback",
		},
		AuthBaseContextPath: "/auth/dup",
	}

	err := mh.AddProvider(opts2)
	if err == nil {
		t.Fatal("expected error for duplicate provider name")
	}
}

func TestAddProviderSharesSessionStore(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)

	err := mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name:         "p1",
			Issuer:       provider.URL,
			ClientId:     testClientID,
			ClientSecret: testClientSecret,
			RedirectUri:  "http://localhost:8080/auth/p1/callback",
		},
		AuthBaseContextPath: "/auth/p1",
	})
	if err != nil {
		t.Fatalf("AddProvider p1: %v", err)
	}

	err = mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name:         "p2",
			Issuer:       provider.URL,
			ClientId:     testClientID,
			ClientSecret: testClientSecret,
			RedirectUri:  "http://localhost:8080/auth/p2/callback",
		},
		AuthBaseContextPath: "/auth/p2",
	})
	if err != nil {
		t.Fatalf("AddProvider p2: %v", err)
	}

	// Both handlers should share the same session store
	if mh.Handlers["p1"].SessionStore != mh.Handlers["p2"].SessionStore {
		t.Error("expected both handlers to share the same SessionStore")
	}
	if mh.Handlers["p1"].SessionStore != mh.SessionStore {
		t.Error("expected handler SessionStore to be the multi-handler's SessionStore")
	}
}

func TestGetDefaultHandlerExplicit(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), &MultiHandlerOptions{
		Session:         defaultTestSessionOpts(),
		DefaultProvider: "second",
	})

	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "first", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/first/callback",
		},
		AuthBaseContextPath: "/auth/first",
	})
	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "second", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/second/callback",
		},
		AuthBaseContextPath: "/auth/second",
	})

	h := mh.GetDefaultHandler()
	if h == nil {
		t.Fatal("expected non-nil default handler")
	}
	if h.Options.Provider.Name != "second" {
		t.Errorf("expected default handler 'second', got %q", h.Options.Provider.Name)
	}
}

func TestGetDefaultHandlerSingleProvider(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)

	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "only", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/only/callback",
		},
		AuthBaseContextPath: "/auth/only",
	})

	h := mh.GetDefaultHandler()
	if h == nil {
		t.Fatal("expected non-nil default handler for single provider")
	}
	if h.Options.Provider.Name != "only" {
		t.Errorf("expected 'only', got %q", h.Options.Provider.Name)
	}
}

func TestGetDefaultHandlerMultipleNoDefault(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)

	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "a", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/a/callback",
		},
		AuthBaseContextPath: "/auth/a",
	})
	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "b", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/b/callback",
		},
		AuthBaseContextPath: "/auth/b",
	})

	h := mh.GetDefaultHandler()
	if h != nil {
		t.Error("expected nil when multiple providers and no default set")
	}
}

func TestLoginURLWithDefault(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), &MultiHandlerOptions{
		Session:         defaultTestSessionOpts(),
		DefaultProvider: "google",
	})

	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "google", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/google/callback",
		},
		AuthBaseUrl:         "http://localhost:8080",
		AuthBaseContextPath: "/auth/google",
	})

	loginURL := mh.LoginURL()
	if loginURL != "http://localhost:8080/auth/google/login" {
		t.Errorf("loginURL: got %q, want %q", loginURL, "http://localhost:8080/auth/google/login")
	}
}

func TestLoginURLWithSelectorURL(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), &MultiHandlerOptions{
		Session:          defaultTestSessionOpts(),
		LoginSelectorUrl: "https://app.example.com/select-login",
	})

	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "a", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/a/callback",
		},
		AuthBaseContextPath: "/auth/a",
	})
	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "b", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/b/callback",
		},
		AuthBaseContextPath: "/auth/b",
	})

	loginURL := mh.LoginURL()
	if loginURL != "https://app.example.com/select-login" {
		t.Errorf("loginURL: got %q, want %q", loginURL, "https://app.example.com/select-login")
	}
}

func TestLoginURLFallbackToOidc(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)

	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "oidc", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/oidc/callback",
		},
		AuthBaseUrl:         "http://localhost:8080",
		AuthBaseContextPath: "/auth/oidc",
	})
	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "google", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/google/callback",
		},
		AuthBaseUrl:         "http://localhost:8080",
		AuthBaseContextPath: "/auth/google",
	})

	// No default, no selector URL, multiple providers → falls back to "oidc"
	loginURL := mh.LoginURL()
	if loginURL != "http://localhost:8080/auth/oidc/login" {
		t.Errorf("loginURL: got %q, want %q", loginURL, "http://localhost:8080/auth/oidc/login")
	}
}

func TestProviderNames(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)

	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "oidc", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/oidc/callback",
		},
		AuthBaseContextPath: "/auth/oidc",
	})
	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "google", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/google/callback",
		},
		AuthBaseContextPath: "/auth/google",
	})

	names := mh.ProviderNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(names))
	}

	nameSet := map[string]bool{}
	for _, n := range names {
		nameSet[n] = true
	}
	if !nameSet["oidc"] || !nameSet["google"] {
		t.Errorf("expected {oidc, google}, got %v", names)
	}
}

// googleTokenHandler returns a token handler that produces Google-style claims (no preferred_username).
func googleTokenHandler(t *testing.T, clientID string) tokenHandler {
	t.Helper()
	return func(serverURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			code := r.FormValue("code")
			if code == "" {
				http.Error(w, "missing code", http.StatusBadRequest)
				return
			}

			idToken := mustSignTestIDToken(serverURL, clientID, "google-user-123", map[string]interface{}{
				"name":        "Google User",
				"email":       "guser@gmail.com",
				"picture":     "https://lh3.googleusercontent.com/photo",
				"given_name":  "Google",
				"family_name": "User",
			})

			resp := map[string]interface{}{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     idToken,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	}
}

func TestE2EMultiHandlerGoogleLogin(t *testing.T) {
	// Create mock providers
	oidcProvider := newMockOIDCProvider(t, testClientID)
	googleProvider := newMockOIDCProviderWithTokenHandler(t, googleTokenHandler(t, testClientID))

	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)

	// Add OIDC provider
	err := mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name:         "oidc",
			Issuer:       oidcProvider.URL,
			ClientId:     testClientID,
			ClientSecret: testClientSecret,
			RedirectUri:  "http://localhost:8080/auth/oidc/callback",
			LogoutUri:    oidcProvider.URL + "/logout",
		},
		AuthBaseContextPath:    "/auth/oidc",
		EnableUserInfoEndpoint: true,
	})
	if err != nil {
		t.Fatalf("AddProvider oidc: %v", err)
	}

	// Add Google provider
	err = mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name:         "google",
			Issuer:       googleProvider.URL,
			ClientId:     testClientID,
			ClientSecret: testClientSecret,
			RedirectUri:  "http://localhost:8080/auth/google/callback",
			ClaimMapper:  GoogleClaimMapper,
		},
		AuthBaseContextPath:    "/auth/google",
		EnableUserInfoEndpoint: true,
	})
	if err != nil {
		t.Fatalf("AddProvider google: %v", err)
	}

	engine := gin.New()
	mh.RegisterRoutes(engine)

	// Login via Google provider
	resp := performRequest(engine, "GET", "/auth/google/login", nil)
	if resp.Code != http.StatusFound {
		t.Fatalf("google login: expected 302, got %d", resp.Code)
	}
	cookies := collectCookies(nil, resp)

	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state in google login redirect")
	}

	// Callback
	callbackURL := fmt.Sprintf("/auth/google/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	if resp.Code != http.StatusFound {
		t.Fatalf("google callback: expected 302, got %d (body: %s)", resp.Code, resp.Body.String())
	}
	cookies = collectCookies(cookies, resp)

	// Verify session via userinfo
	resp = performRequest(engine, "GET", "/auth/google/userinfo", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("google userinfo: expected 200, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var data SessionData
	if err := json.Unmarshal(resp.Body.Bytes(), &data); err != nil {
		t.Fatalf("failed to parse userinfo: %v", err)
	}
	if !data.Authenticated {
		t.Error("expected Authenticated=true")
	}
	if data.Provider != "google" {
		t.Errorf("Provider: got %q, want %q", data.Provider, "google")
	}
	if data.Sub != "google-user-123" {
		t.Errorf("Sub: got %q, want %q", data.Sub, "google-user-123")
	}
	if data.Name != "Google User" {
		t.Errorf("Name: got %q, want %q", data.Name, "Google User")
	}
	if data.Email != "guser@gmail.com" {
		t.Errorf("Email: got %q, want %q", data.Email, "guser@gmail.com")
	}
	if data.Username != "guser" {
		t.Errorf("Username: got %q, want %q (derived from email)", data.Username, "guser")
	}
}

func TestE2EMultiHandlerSharedSession(t *testing.T) {
	// Logging in via Google should result in a session that is also accessible
	// from the OIDC userinfo endpoint (since they share the same session store + cookie).
	oidcProvider := newMockOIDCProvider(t, testClientID)
	googleProvider := newMockOIDCProviderWithTokenHandler(t, googleTokenHandler(t, testClientID))

	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)

	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "oidc", Issuer: oidcProvider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/oidc/callback",
		},
		AuthBaseContextPath:    "/auth/oidc",
		EnableUserInfoEndpoint: true,
	})
	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "google", Issuer: googleProvider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/google/callback",
			ClaimMapper: GoogleClaimMapper,
		},
		AuthBaseContextPath:    "/auth/google",
		EnableUserInfoEndpoint: true,
	})

	engine := gin.New()
	mh.RegisterRoutes(engine)

	// Login via Google
	resp := performRequest(engine, "GET", "/auth/google/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/google/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	cookies = collectCookies(cookies, resp)

	// Access OIDC userinfo endpoint with the same session cookies
	// This should work because the session store is shared
	resp = performRequest(engine, "GET", "/auth/oidc/userinfo", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("oidc userinfo after google login: expected 200, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var data SessionData
	json.Unmarshal(resp.Body.Bytes(), &data)
	if data.Provider != "google" {
		t.Errorf("Provider: got %q, want %q", data.Provider, "google")
	}
	if data.Email != "guser@gmail.com" {
		t.Errorf("Email: got %q, want %q", data.Email, "guser@gmail.com")
	}
}

func TestE2EMultiHandlerOidcProviderField(t *testing.T) {
	// Verify that login via the OIDC provider sets Provider="oidc"
	provider := newMockOIDCProvider(t, testClientID)

	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)
	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "oidc", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/oidc/callback",
			LogoutUri:   provider.URL + "/logout",
		},
		AuthBaseContextPath:    "/auth/oidc",
		EnableUserInfoEndpoint: true,
	})

	engine := gin.New()
	mh.RegisterRoutes(engine)

	// Login via OIDC
	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	cookies = collectCookies(cookies, resp)

	resp = performRequest(engine, "GET", "/auth/oidc/userinfo", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d", resp.Code)
	}

	var data SessionData
	json.Unmarshal(resp.Body.Bytes(), &data)
	if data.Provider != "oidc" {
		t.Errorf("Provider: got %q, want %q", data.Provider, "oidc")
	}
	if data.Username != "testuser" {
		t.Errorf("Username: got %q, want %q", data.Username, "testuser")
	}
}

func TestE2EMultiHandlerUiMiddleware(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)

	mh := newTestMultiHandler(t, defaultTestSessionOpts(), &MultiHandlerOptions{
		Session:         defaultTestSessionOpts(),
		DefaultProvider: "oidc",
	})
	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "oidc", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/oidc/callback",
		},
		AuthBaseUrl:         "http://localhost:8080",
		AuthBaseContextPath: "/auth/oidc",
	})

	engine := gin.New()
	mh.RegisterRoutes(engine)
	engine.GET("/protected", mh.GetUiAuthMiddleware(), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Unauthenticated → redirect to login
	resp := performRequest(engine, "GET", "/protected", nil)
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.Code)
	}
	if loc := resp.Header().Get("Location"); loc != "http://localhost:8080/auth/oidc/login" {
		t.Errorf("expected redirect to oidc login, got %q", loc)
	}
}

func TestE2EMultiHandlerApiMiddleware(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)

	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)
	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "oidc", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/oidc/callback",
		},
		AuthBaseContextPath: "/auth/oidc",
	})

	engine := gin.New()
	mh.RegisterRoutes(engine)
	engine.GET("/api/data", mh.GetApiAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"data": "secret"})
	})

	// Unauthenticated → 401
	resp := performRequest(engine, "GET", "/api/data", nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}

	// Login via OIDC, then access API
	resp = performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	cookies = collectCookies(cookies, resp)

	resp = performRequest(engine, "GET", "/api/data", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 after login, got %d", resp.Code)
	}

	// Verify provider is set in context
	var body map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &body)
	if body["data"] != "secret" {
		t.Errorf("expected data=secret, got %v", body["data"])
	}
}

func TestGetHandler(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	mh := newTestMultiHandler(t, defaultTestSessionOpts(), nil)

	mh.AddProvider(&Options{
		Provider: &ProviderOptions{
			Name: "test", Issuer: provider.URL,
			ClientId: testClientID, ClientSecret: testClientSecret,
			RedirectUri: "http://localhost:8080/auth/test/callback",
		},
		AuthBaseContextPath: "/auth/test",
	})

	h, ok := mh.GetHandler("test")
	if !ok || h == nil {
		t.Fatal("expected to find handler 'test'")
	}

	h, ok = mh.GetHandler("nonexistent")
	if ok || h != nil {
		t.Error("expected nil for nonexistent handler")
	}
}
