package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var (
	testRSAKey  *rsa.PrivateKey
	testJWKSet  jwk.Set
	testJWKPriv jwk.Key
)

func init() {
	gin.SetMode(gin.TestMode)

	var err error
	testRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate RSA key: %v", err))
	}

	pubJWK, err := jwk.Import(testRSAKey.Public())
	if err != nil {
		panic(fmt.Sprintf("failed to import public key: %v", err))
	}
	pubJWK.Set(jwk.KeyIDKey, "test-key-1")
	pubJWK.Set(jwk.AlgorithmKey, "RS256")
	pubJWK.Set(jwk.KeyUsageKey, jwk.ForSignature)

	testJWKSet = jwk.NewSet()
	testJWKSet.AddKey(pubJWK)

	testJWKPriv, err = jwk.Import(testRSAKey)
	if err != nil {
		panic(fmt.Sprintf("failed to import private key: %v", err))
	}
	testJWKPriv.Set(jwk.KeyIDKey, "test-key-1")
	testJWKPriv.Set(jwk.AlgorithmKey, "RS256")
}

// mustSignTestIDToken creates a signed JWT with standard OIDC claims. Panics on error.
func mustSignTestIDToken(issuer, clientID, sub string, extraClaims map[string]any) string {
	tok := jwt.New()
	tok.Set(jwt.IssuerKey, issuer)
	tok.Set(jwt.SubjectKey, sub)
	tok.Set(jwt.AudienceKey, []string{clientID})
	tok.Set(jwt.IssuedAtKey, time.Now().Unix())
	tok.Set(jwt.ExpirationKey, time.Now().Add(10*time.Minute).Unix())

	for k, v := range extraClaims {
		tok.Set(k, v)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), testJWKPriv))
	if err != nil {
		panic(fmt.Sprintf("failed to sign test ID token: %v", err))
	}
	return string(signed)
}

// tokenHandler is a function that handles the /token endpoint.
// It receives the server URL and returns the HTTP handler.
type tokenHandler func(serverURL string) http.HandlerFunc

// defaultTokenHandler returns a valid token response with a properly signed ID token.
func defaultTokenHandler(t *testing.T, clientID string) tokenHandler {
	t.Helper()
	return func(serverURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			code := r.FormValue("code")
			if code == "" {
				http.Error(w, "missing code", http.StatusBadRequest)
				return
			}

			idToken := mustSignTestIDToken(serverURL, clientID, "test-user-sub", map[string]interface{}{
				"name":               "Test User",
				"email":              "test@example.com",
				"preferred_username": "testuser",
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

// newMockOIDCProviderWithTokenHandler creates a mock OIDC provider with a custom token handler.
func newMockOIDCProviderWithTokenHandler(t *testing.T, th tokenHandler) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	var server *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := server.URL
		doc := map[string]interface{}{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
			"userinfo_endpoint":      issuer + "/userinfo",
			"end_session_endpoint":   issuer + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"subject_types_supported":               []string{"public"},
			"response_types_supported":              []string{"code"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testJWKSet)
	})

	// Use a wrapper so the token handler can access server.URL
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		th(server.URL)(w, r)
	})

	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// newMockOIDCProvider creates an httptest.Server with the default token handler.
func newMockOIDCProvider(t *testing.T, clientID string) *httptest.Server {
	t.Helper()
	return newMockOIDCProviderWithTokenHandler(t, defaultTokenHandler(t, clientID))
}

const testClientID = "test-client-id"
const testClientSecret = "test-client-secret"
const testSessionSigningKey = "signing-key-at-least-32-bytes!!!"
const testSessionEncryptionKey = "01234567890123456789012345678901"

// newTestE2EHandler creates a real Handler and gin.Engine wired to a mock OIDC provider.
func newTestE2EHandler(t *testing.T, provider *httptest.Server) (*Handler, *gin.Engine) {
	t.Helper()

	handler, err := NewHandler(&Options{
		Provider: &ProviderOptions{
			Issuer:       provider.URL,
			ClientId:     testClientID,
			ClientSecret: testClientSecret,
			RedirectUri:  "http://localhost:8080/auth/oidc/callback",
			LogoutUri:    provider.URL + "/logout",
		},
		Session: &SessionOptions{
			SecretSigningKey:    testSessionSigningKey,
			SecretEncryptionKey: testSessionEncryptionKey,
			Name:                "e2e-session",
			MaxAge:              3600,
		},
		EnableUserInfoEndpoint: true,
	})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	engine := gin.New()
	handler.RegisterRoutes(engine)

	return handler, engine
}

// performRequest executes an HTTP request against a gin engine with optional cookies.
func performRequest(engine *gin.Engine, method, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// collectCookies merges cookies from a response into an existing cookie jar, handling overwrites.
func collectCookies(existing []*http.Cookie, resp *httptest.ResponseRecorder) []*http.Cookie {
	newCookies := resp.Result().Cookies()
	// Build map of existing by name
	byName := make(map[string]*http.Cookie)
	for _, c := range existing {
		byName[c.Name] = c
	}
	for _, c := range newCookies {
		if c.MaxAge < 0 {
			delete(byName, c.Name)
		} else {
			byName[c.Name] = c
		}
	}
	result := make([]*http.Cookie, 0, len(byName))
	for _, c := range byName {
		result = append(result, c)
	}
	return result
}

// doLogin performs the full login flow and returns session cookies.
func doLogin(t *testing.T, engine *gin.Engine) []*http.Cookie {
	t.Helper()

	// Step 1: GET /auth/oidc/login → 302 redirect to provider
	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	if resp.Code != http.StatusFound {
		t.Fatalf("login: expected 302, got %d", resp.Code)
	}
	cookies := collectCookies(nil, resp)

	// Extract state from redirect URL
	loc, err := url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("login: failed to parse redirect URL: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("login: no state in redirect URL")
	}

	// Step 2: GET /auth/oidc/callback?state=...&code=test-code → 302 redirect to /
	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	if resp.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d (body: %s)", resp.Code, resp.Body.String())
	}
	cookies = collectCookies(cookies, resp)

	return cookies
}

func TestE2ELoginFlow(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	_, engine := newTestE2EHandler(t, provider)

	// Complete login
	cookies := doLogin(t, engine)

	// Verify session via userinfo
	resp := performRequest(engine, "GET", "/auth/oidc/userinfo", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var data SessionData
	if err := json.Unmarshal(resp.Body.Bytes(), &data); err != nil {
		t.Fatalf("userinfo: failed to parse response: %v", err)
	}
	if !data.Authenticated {
		t.Error("expected Authenticated=true")
	}
	if data.Sub != "test-user-sub" {
		t.Errorf("Sub: got %q, want %q", data.Sub, "test-user-sub")
	}
	if data.Name != "Test User" {
		t.Errorf("Name: got %q, want %q", data.Name, "Test User")
	}
	if data.Email != "test@example.com" {
		t.Errorf("Email: got %q, want %q", data.Email, "test@example.com")
	}
	if data.Username != "testuser" {
		t.Errorf("Username: got %q, want %q", data.Username, "testuser")
	}
}

func TestE2ELoginRedirectURL(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	_, engine := newTestE2EHandler(t, provider)

	// Login should redirect to the provider's authorization endpoint
	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.Code)
	}

	loc := resp.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}

	if !strings.HasPrefix(loc, provider.URL+"/auth") {
		t.Errorf("expected redirect to provider auth endpoint, got %s", loc)
	}
	if parsed.Query().Get("state") == "" {
		t.Error("expected state parameter in redirect")
	}
	if parsed.Query().Get("client_id") != testClientID {
		t.Errorf("client_id: got %q, want %q", parsed.Query().Get("client_id"), testClientID)
	}
	if parsed.Query().Get("response_type") != "code" {
		t.Errorf("response_type: got %q, want %q", parsed.Query().Get("response_type"), "code")
	}
}

func TestE2ELoginFlowWithFlashRedirect(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	handler, engine := newTestE2EHandler(t, provider)

	// Start login to create a session
	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	if resp.Code != http.StatusFound {
		t.Fatalf("login: expected 302, got %d", resp.Code)
	}
	cookies := collectCookies(nil, resp)

	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	// Set a flash on the same session (simulating what happens when the flash is set
	// within the same session that login uses)
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	err := handler.SessionStore.SetStringFlash(req, w, "/dashboard")
	if err != nil {
		t.Fatalf("SetStringFlash failed: %v", err)
	}
	cookies = collectCookies(cookies, w)

	// Callback should redirect to /dashboard (the flash URL)
	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	if resp.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	redirectTo := resp.Header().Get("Location")
	if redirectTo != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %q", redirectTo)
	}
}

func TestE2ELogout(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	_, engine := newTestE2EHandler(t, provider)

	cookies := doLogin(t, engine)

	// Logout
	resp := performRequest(engine, "GET", "/auth/oidc/logout", cookies)
	if resp.Code != http.StatusFound {
		t.Fatalf("logout: expected 302, got %d", resp.Code)
	}
	logoutLoc := resp.Header().Get("Location")
	if !strings.HasPrefix(logoutLoc, provider.URL+"/logout") {
		t.Errorf("expected redirect to provider logout, got %s", logoutLoc)
	}

	// Session should be destroyed — userinfo is behind UI middleware, so it redirects to login
	cookies = collectCookies(cookies, resp)
	resp = performRequest(engine, "GET", "/auth/oidc/userinfo", cookies)
	if resp.Code != http.StatusFound {
		t.Errorf("userinfo after logout: expected 302 redirect to login, got %d", resp.Code)
	}
	if loc := resp.Header().Get("Location"); loc != "/auth/oidc/login" {
		t.Errorf("expected redirect to /auth/oidc/login, got %q", loc)
	}
}

func TestE2EUiMiddlewareUnauthenticated(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	handler, engine := newTestE2EHandler(t, provider)

	engine.GET("/protected", handler.GetUiAuthMiddleware(), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	resp := performRequest(engine, "GET", "/protected", nil)
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", resp.Code)
	}
	loc := resp.Header().Get("Location")
	if loc != "/auth/oidc/login" {
		t.Errorf("expected redirect to /auth/oidc/login, got %q", loc)
	}
}

func TestE2EUiMiddlewareAuthenticated(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	handler, engine := newTestE2EHandler(t, provider)

	engine.GET("/protected", handler.GetUiAuthMiddleware(), func(c *gin.Context) {
		c.String(http.StatusOK, "protected content")
	})

	cookies := doLogin(t, engine)

	resp := performRequest(engine, "GET", "/protected", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", resp.Code, resp.Body.String())
	}
	if resp.Body.String() != "protected content" {
		t.Errorf("expected 'protected content', got %q", resp.Body.String())
	}
}

func TestE2EApiMiddlewareUnauthenticated(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	handler, engine := newTestE2EHandler(t, provider)

	engine.GET("/api/data", handler.GetApiAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"data": "secret"})
	})

	resp := performRequest(engine, "GET", "/api/data", nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}

	var body map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &body)
	if body["error"] != "unauthorized" {
		t.Errorf("expected error 'unauthorized', got %v", body["error"])
	}
}

func TestE2EApiMiddlewareAuthenticated(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	handler, engine := newTestE2EHandler(t, provider)

	engine.GET("/api/data", handler.GetApiAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"data": "secret"})
	})

	cookies := doLogin(t, engine)

	resp := performRequest(engine, "GET", "/api/data", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
}

func TestE2ECallbackStateMismatch(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	_, engine := newTestE2EHandler(t, provider)

	// Start login to get a session with state
	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)

	// Callback with wrong state
	resp = performRequest(engine, "GET", "/auth/oidc/callback?state=wrong-state&code=test-code", cookies)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body: %s)", resp.Code, resp.Body.String())
	}
}

func TestE2ECallbackNoCode(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	_, engine := newTestE2EHandler(t, provider)

	// Start login
	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)

	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	// Callback with correct state but no code
	resp = performRequest(engine, "GET", fmt.Sprintf("/auth/oidc/callback?state=%s", url.QueryEscape(state)), cookies)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body: %s)", resp.Code, resp.Body.String())
	}
}

func TestE2ECallbackDefaultRedirect(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	_, engine := newTestE2EHandler(t, provider)

	// Do full login without any flash set → should redirect to /
	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)

	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.Code)
	}
	if resp.Header().Get("Location") != "/" {
		t.Errorf("expected redirect to /, got %q", resp.Header().Get("Location"))
	}
}

func TestE2ECallbackNoCookies(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	_, engine := newTestE2EHandler(t, provider)

	// Callback with no session cookies at all → state mismatch (savedState is "")
	resp := performRequest(engine, "GET", "/auth/oidc/callback?state=some-state&code=test-code", nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var body map[string]any
	json.Unmarshal(resp.Body.Bytes(), &body)
	if body["error"] != "state mismatch" {
		t.Errorf("expected 'state mismatch' error, got %v", body["error"])
	}
}

func TestE2ECallbackEmptyState(t *testing.T) {
	provider := newMockOIDCProvider(t, testClientID)
	_, engine := newTestE2EHandler(t, provider)

	// Start login to get cookies
	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)

	// Callback with empty state parameter
	resp = performRequest(engine, "GET", "/auth/oidc/callback?state=&code=test-code", cookies)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body: %s)", resp.Code, resp.Body.String())
	}
}

func TestE2ECallbackTokenExchangeFailure(t *testing.T) {
	// Provider returns an error on token exchange
	provider := newMockOIDCProviderWithTokenHandler(t, func(serverURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "authorization code expired",
			})
		}
	})
	_, engine := newTestE2EHandler(t, provider)

	// Start login
	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	// Callback — token exchange will fail
	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=expired-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var body map[string]any
	json.Unmarshal(resp.Body.Bytes(), &body)
	if body["error"] != "failed to exchange token" {
		t.Errorf("expected 'failed to exchange token' error, got %v", body["error"])
	}
}

func TestE2ECallbackNoIDToken(t *testing.T) {
	// Provider returns a valid token response but without id_token
	provider := newMockOIDCProviderWithTokenHandler(t, func(serverURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]any{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				// no id_token
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	})
	_, engine := newTestE2EHandler(t, provider)

	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var body map[string]any
	json.Unmarshal(resp.Body.Bytes(), &body)
	if body["error"] != "no id_token" {
		t.Errorf("expected 'no id_token' error, got %v", body["error"])
	}
}

func TestE2ECallbackInvalidIDToken(t *testing.T) {
	// Provider returns a garbage string as id_token
	provider := newMockOIDCProviderWithTokenHandler(t, func(serverURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]any{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     "not-a-valid-jwt",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	})
	_, engine := newTestE2EHandler(t, provider)

	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var body map[string]any
	json.Unmarshal(resp.Body.Bytes(), &body)
	if body["error"] != "failed to verify token" {
		t.Errorf("expected 'failed to verify token' error, got %v", body["error"])
	}
}

func TestE2ECallbackExpiredIDToken(t *testing.T) {
	// Provider returns an expired ID token
	provider := newMockOIDCProviderWithTokenHandler(t, func(serverURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Create a token that expired 1 hour ago
			tok := jwt.New()
			tok.Set(jwt.IssuerKey, serverURL)
			tok.Set(jwt.SubjectKey, "test-user-sub")
			tok.Set(jwt.AudienceKey, []string{testClientID})
			tok.Set(jwt.IssuedAtKey, time.Now().Add(-2*time.Hour).Unix())
			tok.Set(jwt.ExpirationKey, time.Now().Add(-1*time.Hour).Unix())
			tok.Set("name", "Test User")
			tok.Set("email", "test@example.com")
			tok.Set("preferred_username", "testuser")

			signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), testJWKPriv))
			if err != nil {
				http.Error(w, "signing failed", http.StatusInternalServerError)
				return
			}

			resp := map[string]any{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     string(signed),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	})
	_, engine := newTestE2EHandler(t, provider)

	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var body map[string]any
	json.Unmarshal(resp.Body.Bytes(), &body)
	if body["error"] != "failed to verify token" {
		t.Errorf("expected 'failed to verify token' error, got %v", body["error"])
	}
}

func TestE2ECallbackWrongAudience(t *testing.T) {
	// Provider returns an ID token with wrong audience
	provider := newMockOIDCProviderWithTokenHandler(t, func(serverURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Sign token with wrong audience
			idToken := mustSignTestIDToken(serverURL, "wrong-client-id", "test-user-sub", map[string]any{
				"name":               "Test User",
				"email":              "test@example.com",
				"preferred_username": "testuser",
			})

			resp := map[string]any{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     idToken,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	})
	_, engine := newTestE2EHandler(t, provider)

	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var body map[string]any
	json.Unmarshal(resp.Body.Bytes(), &body)
	if body["error"] != "failed to verify token" {
		t.Errorf("expected 'failed to verify token' error, got %v", body["error"])
	}
}

func TestE2ECallbackWrongIssuer(t *testing.T) {
	// Provider returns an ID token with wrong issuer
	provider := newMockOIDCProviderWithTokenHandler(t, func(serverURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			idToken := mustSignTestIDToken("https://wrong-issuer.example.com", testClientID, "test-user-sub", map[string]any{
				"name":               "Test User",
				"email":              "test@example.com",
				"preferred_username": "testuser",
			})

			resp := map[string]any{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     idToken,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	})
	_, engine := newTestE2EHandler(t, provider)

	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var body map[string]any
	json.Unmarshal(resp.Body.Bytes(), &body)
	if body["error"] != "failed to verify token" {
		t.Errorf("expected 'failed to verify token' error, got %v", body["error"])
	}
}
