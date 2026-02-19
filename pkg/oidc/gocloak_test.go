package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// mockKeycloakAdminConfig configures the mock Keycloak admin API responses.
type mockKeycloakAdminConfig struct {
	RealmRoles  []string
	ClientRoles []string
	Groups      []string // group paths
	ClientUUID  string
	ClientName  string
	// If true, the realm roles endpoint returns 500
	FailRolesFetch bool
}

// newMockKeycloakAdmin creates a mock Keycloak admin API server that handles
// token, role, group, and client endpoints used by gocloak.
func newMockKeycloakAdmin(t *testing.T, cfg *mockKeycloakAdminConfig) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		// Token endpoint: /realms/{realm}/protocol/openid-connect/token
		if strings.Contains(path, "/protocol/openid-connect/token") && r.Method == "POST" {
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "mock-admin-token",
				"token_type":   "Bearer",
				"expires_in":   300,
			})
			return
		}

		// Realm roles by user: /admin/realms/{realm}/users/{id}/role-mappings/realm
		if strings.HasSuffix(path, "/role-mappings/realm") {
			if cfg.FailRolesFetch {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
				return
			}
			roles := make([]map[string]any, 0)
			for _, name := range cfg.RealmRoles {
				roles = append(roles, map[string]any{"id": "uuid-" + name, "name": name})
			}
			json.NewEncoder(w).Encode(roles)
			return
		}

		// Client roles by user: /admin/realms/{realm}/users/{id}/role-mappings/clients/{uuid}
		if strings.Contains(path, "/role-mappings/clients/") {
			roles := make([]map[string]any, 0)
			for _, name := range cfg.ClientRoles {
				roles = append(roles, map[string]any{"id": "uuid-" + name, "name": name})
			}
			json.NewEncoder(w).Encode(roles)
			return
		}

		// User groups: /admin/realms/{realm}/users/{id}/groups
		if strings.HasSuffix(path, "/groups") && strings.Contains(path, "/users/") {
			groups := make([]map[string]any, 0)
			for _, gpath := range cfg.Groups {
				name := strings.TrimPrefix(gpath, "/")
				groups = append(groups, map[string]any{
					"id":   "uuid-" + name,
					"name": name,
					"path": gpath,
				})
			}
			json.NewEncoder(w).Encode(groups)
			return
		}

		// Get clients: /admin/realms/{realm}/clients
		if strings.HasSuffix(path, "/clients") && !strings.Contains(path, "/users/") {
			clients := []map[string]any{
				{
					"id":       cfg.ClientUUID,
					"clientId": cfg.ClientName,
				},
			}
			json.NewEncoder(w).Encode(clients)
			return
		}

		http.NotFound(w, r)
	}))

	t.Cleanup(server.Close)
	return server
}

func newTestGocloakOptions(adminURL string) *GocloakOptions {
	return &GocloakOptions{
		ServerURL:  adminURL,
		Realm:      "test-realm",
		AuthMethod: "password",
		Username:   "admin",
		Password:   "admin",
	}
}

func newTestE2EHandlerWithGocloak(t *testing.T, provider *httptest.Server, gcOpts *GocloakOptions) (*Handler, *gin.Engine) {
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
			Name:                "e2e-gc-session",
			MaxAge:              3600,
		},
		EnableUserInfoEndpoint: true,
		Gocloak:                gcOpts,
	})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	engine := gin.New()
	handler.RegisterRoutes(engine)

	return handler, engine
}

func TestNewGocloakClientValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    *GocloakOptions
		wantErr string
	}{
		{
			name:    "empty server URL",
			opts:    &GocloakOptions{Realm: "test"},
			wantErr: "server URL cannot be empty",
		},
		{
			name:    "empty realm",
			opts:    &GocloakOptions{ServerURL: "http://localhost"},
			wantErr: "realm cannot be empty",
		},
		{
			name: "invalid auth method",
			opts: &GocloakOptions{
				ServerURL:  "http://localhost",
				Realm:      "test",
				AuthMethod: "invalid",
			},
			wantErr: "must be 'password' or 'client_credentials'",
		},
		{
			name: "password auth missing credentials",
			opts: &GocloakOptions{
				ServerURL:  "http://localhost",
				Realm:      "test",
				AuthMethod: "password",
			},
			wantErr: "username and password are required",
		},
		{
			name: "client_credentials missing credentials",
			opts: &GocloakOptions{
				ServerURL:  "http://localhost",
				Realm:      "test",
				AuthMethod: "client_credentials",
			},
			wantErr: "client ID and secret are required",
		},
		{
			name: "valid password auth",
			opts: &GocloakOptions{
				ServerURL: "http://localhost",
				Realm:     "test",
				Username:  "admin",
				Password:  "admin",
			},
			wantErr: "",
		},
		{
			name: "valid client_credentials auth",
			opts: &GocloakOptions{
				ServerURL:    "http://localhost",
				Realm:        "test",
				AuthMethod:   "client_credentials",
				ClientID:     "my-client",
				ClientSecret: "my-secret",
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newGocloakClient(tt.opts)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestGocloakCallbackPopulatesRolesAndGroups(t *testing.T) {
	oidcProvider := newMockOIDCProvider(t, testClientID)
	kcAdmin := newMockKeycloakAdmin(t, &mockKeycloakAdminConfig{
		RealmRoles:  []string{"admin", "user"},
		ClientRoles: []string{"editor", "viewer"},
		Groups:      []string{"/admins", "/users"},
		ClientUUID:  "uuid-test-app",
		ClientName:  "test-app",
	})

	gcOpts := newTestGocloakOptions(kcAdmin.URL)
	gcOpts.ClientRolesClientID = "test-app"
	_, engine := newTestE2EHandlerWithGocloak(t, oidcProvider, gcOpts)

	cookies := doLogin(t, engine)

	// Check session data via userinfo
	resp := performRequest(engine, "GET", "/auth/oidc/userinfo", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var data SessionData
	if err := json.Unmarshal(resp.Body.Bytes(), &data); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify realm roles
	if len(data.RealmRoles) != 2 {
		t.Fatalf("expected 2 realm roles, got %d: %v", len(data.RealmRoles), data.RealmRoles)
	}
	realmRoleSet := toSet(data.RealmRoles)
	if !realmRoleSet["admin"] || !realmRoleSet["user"] {
		t.Errorf("expected realm roles [admin, user], got %v", data.RealmRoles)
	}

	// Verify client roles
	if len(data.ClientRoles) != 2 {
		t.Fatalf("expected 2 client roles, got %d: %v", len(data.ClientRoles), data.ClientRoles)
	}
	clientRoleSet := toSet(data.ClientRoles)
	if !clientRoleSet["editor"] || !clientRoleSet["viewer"] {
		t.Errorf("expected client roles [editor, viewer], got %v", data.ClientRoles)
	}

	// Verify groups
	if len(data.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d: %v", len(data.Groups), data.Groups)
	}
	groupSet := toSet(data.Groups)
	if !groupSet["/admins"] || !groupSet["/users"] {
		t.Errorf("expected groups [/admins, /users], got %v", data.Groups)
	}
}

func TestGocloakCallbackNoClientRolesWhenNotConfigured(t *testing.T) {
	oidcProvider := newMockOIDCProvider(t, testClientID)
	kcAdmin := newMockKeycloakAdmin(t, &mockKeycloakAdminConfig{
		RealmRoles: []string{"user"},
		Groups:     []string{"/users"},
	})

	gcOpts := newTestGocloakOptions(kcAdmin.URL)
	// No ClientRolesClientID set
	_, engine := newTestE2EHandlerWithGocloak(t, oidcProvider, gcOpts)

	cookies := doLogin(t, engine)

	resp := performRequest(engine, "GET", "/auth/oidc/userinfo", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var data SessionData
	json.Unmarshal(resp.Body.Bytes(), &data)

	if len(data.RealmRoles) != 1 || data.RealmRoles[0] != "user" {
		t.Errorf("expected realm roles [user], got %v", data.RealmRoles)
	}
	if len(data.ClientRoles) != 0 {
		t.Errorf("expected no client roles, got %v", data.ClientRoles)
	}
	if len(data.Groups) != 1 || data.Groups[0] != "/users" {
		t.Errorf("expected groups [/users], got %v", data.Groups)
	}
}

func TestGocloakCallbackDeniedMissingRealmRole(t *testing.T) {
	oidcProvider := newMockOIDCProvider(t, testClientID)
	kcAdmin := newMockKeycloakAdmin(t, &mockKeycloakAdminConfig{
		RealmRoles: []string{"user"}, // has "user" but not "admin"
		Groups:     []string{"/users"},
	})

	gcOpts := newTestGocloakOptions(kcAdmin.URL)
	gcOpts.RequiredRealmRoles = []string{"admin"} // requires "admin"
	_, engine := newTestE2EHandlerWithGocloak(t, oidcProvider, gcOpts)

	// Manual login flow (can't use doLogin since callback returns 403)
	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var body map[string]any
	json.Unmarshal(resp.Body.Bytes(), &body)
	if body["error"] != "forbidden" {
		t.Errorf("expected 'forbidden' error, got %v", body["error"])
	}
	detail, _ := body["detail"].(string)
	if !strings.Contains(detail, "realm role") {
		t.Errorf("expected detail about realm role, got %q", detail)
	}
}

func TestGocloakCallbackDeniedMissingClientRole(t *testing.T) {
	oidcProvider := newMockOIDCProvider(t, testClientID)
	kcAdmin := newMockKeycloakAdmin(t, &mockKeycloakAdminConfig{
		RealmRoles:  []string{"user"},
		ClientRoles: []string{"viewer"}, // has "viewer" but not "editor"
		Groups:      []string{"/users"},
		ClientUUID:  "uuid-test-app",
		ClientName:  "test-app",
	})

	gcOpts := newTestGocloakOptions(kcAdmin.URL)
	gcOpts.ClientRolesClientID = "test-app"
	gcOpts.RequiredClientRoles = []string{"editor"} // requires "editor"
	_, engine := newTestE2EHandlerWithGocloak(t, oidcProvider, gcOpts)

	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var body map[string]any
	json.Unmarshal(resp.Body.Bytes(), &body)
	detail, _ := body["detail"].(string)
	if !strings.Contains(detail, "client role") {
		t.Errorf("expected detail about client role, got %q", detail)
	}
}

func TestGocloakCallbackDeniedMissingGroup(t *testing.T) {
	oidcProvider := newMockOIDCProvider(t, testClientID)
	kcAdmin := newMockKeycloakAdmin(t, &mockKeycloakAdminConfig{
		RealmRoles: []string{"user"},
		Groups:     []string{"/users"}, // has "/users" but not "/admins"
	})

	gcOpts := newTestGocloakOptions(kcAdmin.URL)
	gcOpts.RequiredGroups = []string{"/admins"} // requires "/admins"
	_, engine := newTestE2EHandlerWithGocloak(t, oidcProvider, gcOpts)

	resp := performRequest(engine, "GET", "/auth/oidc/login", nil)
	cookies := collectCookies(nil, resp)
	loc, _ := url.Parse(resp.Header().Get("Location"))
	state := loc.Query().Get("state")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?state=%s&code=test-code", url.QueryEscape(state))
	resp = performRequest(engine, "GET", callbackURL, cookies)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var body map[string]any
	json.Unmarshal(resp.Body.Bytes(), &body)
	detail, _ := body["detail"].(string)
	if !strings.Contains(detail, "group") {
		t.Errorf("expected detail about group, got %q", detail)
	}
}

func TestGocloakCallbackInfraError(t *testing.T) {
	oidcProvider := newMockOIDCProvider(t, testClientID)
	kcAdmin := newMockKeycloakAdmin(t, &mockKeycloakAdminConfig{
		FailRolesFetch: true,
	})

	gcOpts := newTestGocloakOptions(kcAdmin.URL)
	_, engine := newTestE2EHandlerWithGocloak(t, oidcProvider, gcOpts)

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
	if body["error"] != "failed to fetch authorization" {
		t.Errorf("expected 'failed to fetch authorization' error, got %v", body["error"])
	}
}

func TestGocloakMiddlewareSetsContextValues(t *testing.T) {
	oidcProvider := newMockOIDCProvider(t, testClientID)
	kcAdmin := newMockKeycloakAdmin(t, &mockKeycloakAdminConfig{
		RealmRoles:  []string{"admin"},
		ClientRoles: []string{"editor"},
		Groups:      []string{"/admins"},
		ClientUUID:  "uuid-test-app",
		ClientName:  "test-app",
	})

	gcOpts := newTestGocloakOptions(kcAdmin.URL)
	gcOpts.ClientRolesClientID = "test-app"
	handler, engine := newTestE2EHandlerWithGocloak(t, oidcProvider, gcOpts)

	var capturedRealmRoles, capturedClientRoles, capturedGroups []string
	var capturedSessionData *SessionData

	engine.GET("/test-ui", handler.GetUiAuthMiddleware(), func(c *gin.Context) {
		if v, ok := c.Get("realmRoles"); ok && v != nil {
			capturedRealmRoles = v.([]string)
		}
		if v, ok := c.Get("clientRoles"); ok && v != nil {
			capturedClientRoles = v.([]string)
		}
		if v, ok := c.Get("groups"); ok && v != nil {
			capturedGroups = v.([]string)
		}
		if v, ok := c.Get("sessionData"); ok && v != nil {
			capturedSessionData = v.(*SessionData)
		}
		c.String(http.StatusOK, "ok")
	})

	cookies := doLogin(t, engine)

	resp := performRequest(engine, "GET", "/test-ui", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	if len(capturedRealmRoles) != 1 || capturedRealmRoles[0] != "admin" {
		t.Errorf("expected realmRoles [admin], got %v", capturedRealmRoles)
	}
	if len(capturedClientRoles) != 1 || capturedClientRoles[0] != "editor" {
		t.Errorf("expected clientRoles [editor], got %v", capturedClientRoles)
	}
	if len(capturedGroups) != 1 || capturedGroups[0] != "/admins" {
		t.Errorf("expected groups [/admins], got %v", capturedGroups)
	}
	if capturedSessionData == nil {
		t.Fatal("expected sessionData in context")
	}
	if capturedSessionData.Sub != "test-user-sub" {
		t.Errorf("expected sub 'test-user-sub', got %q", capturedSessionData.Sub)
	}
}

func TestGocloakApiMiddlewareSetsContextValues(t *testing.T) {
	oidcProvider := newMockOIDCProvider(t, testClientID)
	kcAdmin := newMockKeycloakAdmin(t, &mockKeycloakAdminConfig{
		RealmRoles: []string{"user"},
		Groups:     []string{"/users"},
	})

	gcOpts := newTestGocloakOptions(kcAdmin.URL)
	handler, engine := newTestE2EHandlerWithGocloak(t, oidcProvider, gcOpts)

	var capturedRealmRoles []string
	var capturedGroups []string

	engine.GET("/test-api", handler.GetApiAuthMiddleware(), func(c *gin.Context) {
		if v, ok := c.Get("realmRoles"); ok && v != nil {
			capturedRealmRoles = v.([]string)
		}
		if v, ok := c.Get("groups"); ok && v != nil {
			capturedGroups = v.([]string)
		}
		c.JSON(http.StatusOK, gin.H{"data": "secret"})
	})

	cookies := doLogin(t, engine)

	resp := performRequest(engine, "GET", "/test-api", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	if len(capturedRealmRoles) != 1 || capturedRealmRoles[0] != "user" {
		t.Errorf("expected realmRoles [user], got %v", capturedRealmRoles)
	}
	if len(capturedGroups) != 1 || capturedGroups[0] != "/users" {
		t.Errorf("expected groups [/users], got %v", capturedGroups)
	}
}

func TestGocloakCallbackRequiredRolesSatisfied(t *testing.T) {
	oidcProvider := newMockOIDCProvider(t, testClientID)
	kcAdmin := newMockKeycloakAdmin(t, &mockKeycloakAdminConfig{
		RealmRoles:  []string{"admin", "user"},
		ClientRoles: []string{"editor"},
		Groups:      []string{"/admins", "/users"},
		ClientUUID:  "uuid-test-app",
		ClientName:  "test-app",
	})

	gcOpts := newTestGocloakOptions(kcAdmin.URL)
	gcOpts.ClientRolesClientID = "test-app"
	gcOpts.RequiredRealmRoles = []string{"admin"}
	gcOpts.RequiredClientRoles = []string{"editor"}
	gcOpts.RequiredGroups = []string{"/admins"}
	_, engine := newTestE2EHandlerWithGocloak(t, oidcProvider, gcOpts)

	// Login should succeed since all required roles/groups are present
	cookies := doLogin(t, engine)

	resp := performRequest(engine, "GET", "/auth/oidc/userinfo", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d (body: %s)", resp.Code, resp.Body.String())
	}

	var data SessionData
	json.Unmarshal(resp.Body.Bytes(), &data)

	if !data.Authenticated {
		t.Error("expected Authenticated=true")
	}
	if len(data.RealmRoles) != 2 {
		t.Errorf("expected 2 realm roles, got %v", data.RealmRoles)
	}
}
