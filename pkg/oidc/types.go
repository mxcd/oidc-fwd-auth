package oidc

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
)

// PostLoginHook is called after successful OIDC authentication, before the redirect.
// Receives the Gin context and the authenticated session data (including roles/groups if Gocloak is configured).
// Return an error to abort the login and respond with HTTP 500.
type PostLoginHook func(c *gin.Context, sessionData *SessionData) error

type Options struct {
	// OIDC provider configuration
	Provider *ProviderOptions
	// Session configuration
	Session *SessionOptions
	// URL to redirect to after logout
	// if not set, defaults to "/"
	PostLogoutRedirectUri string
	// Base URL of the fwd auth oidc endpoints
	// defaults to "http://localhost:8080"
	AuthBaseUrl string
	// Base context path for the OIDC authentication endpoints
	// defaults to "/auth/oidc"
	AuthBaseContextPath string
	// Enables the /userinfo endpoint
	EnableUserInfoEndpoint bool
	// Gocloak configuration for Keycloak role/group introspection
	// if nil, gocloak integration is disabled
	Gocloak *GocloakOptions
	// PostLoginHook is called after successful authentication and session creation,
	// before redirecting the user. Use this to sync users to a local database,
	// create additional sessions, or perform other post-login actions.
	// If the hook returns an error, the login is aborted with HTTP 500.
	PostLoginHook PostLoginHook
	// PostLogoutHook is called after the OIDC session is destroyed, before redirecting.
	// Use this to destroy additional sessions or perform cleanup.
	PostLogoutHook func(c *gin.Context)
}

type GocloakOptions struct {
	// Keycloak base URL (e.g. https://keycloak.example.com)
	ServerURL string
	// Realm for admin API calls
	Realm string
	// Authentication method: "password" (default) or "client_credentials"
	AuthMethod string
	// Username for password auth
	Username string
	// Password for password auth
	Password string
	// Client ID for client_credentials auth
	ClientID string
	// Client secret for client_credentials auth
	ClientSecret string
	// Required realm roles — deny access if user lacks any
	RequiredRealmRoles []string
	// Required client roles — deny access if user lacks any
	RequiredClientRoles []string
	// Client ID for client role introspection
	ClientRolesClientID string
	// Required groups (by path) — deny access if user lacks any
	RequiredGroups []string
}

type Handler struct {
	Options      *Options
	Provider     *oidc.Provider
	OAuth2Config *oauth2.Config
	Verifier     *oidc.IDTokenVerifier
	SessionStore *SessionStore
	gocloak      *gocloakClient
}

type SessionStore struct {
	Options *SessionOptions
	store   sessions.Store
	cache   sessionCache
}

type SessionOptions struct {
	// key for signing session cookies
	SecretSigningKey string
	// key for encrypting session cookies
	// must be either 32 or 64 bytes long
	SecretEncryptionKey string
	// name of the session cookie
	Name string
	// domain for the session cookie
	Domain string
	// max age of the session cookie in seconds
	// defaults to 86400 (1 day)
	MaxAge int
	Secure bool
	// max number of sessions to keep in the cache
	// defaults to 10000
	CacheSize int
	// TTL for cache entries
	// defaults to MaxAge duration
	CacheTTL time.Duration
	// Redis configuration for distributed sessions
	// if nil, uses local-only cache (default)
	Redis *RedisSessionOptions
}

type RedisSessionOptions struct {
	Host              string
	Port              int
	Password          string
	DB                int
	TTL               time.Duration
	KeyPrefix         string
	PubSub            bool
	PubSubChannelName string
	LocalTTL          time.Duration
	RemoteAsync       bool
	Preload           bool
}

type ProviderOptions struct {
	// URL of the OIDC provider
	// For keycloak, use the realm base url, e.g. https://keycloak.example.com/realms/<realm-name>
	Issuer string
	// OIDC client id configured in the provider
	ClientId string
	// OIDC client secret configured in the provider
	ClientSecret string
	// fully qualified redirect URI for OIDC callbacks
	// e.g. https://your-domain.com/auth/oidc/callback
	RedirectUri string
	// URL to redirect to for logout
	LogoutUri string
	// oidc scopes to request
	// if not set, defaults to openid, profile, email
	Scopes []string
	// Additional scopes to request on top the default ones
	ExtraScopes []string
}

type SessionData struct {
	Authenticated bool
	Sub           string
	Name          string
	Username      string
	Email         string
	Claims        map[string]interface{}
	RealmRoles    []string
	ClientRoles   []string
	Groups        []string
}

type sessionEntry struct {
	Data    *SessionData      `json:"data,omitempty"`
	Values  map[string]string `json:"values,omitempty"`
	Flashes []string          `json:"flashes,omitempty"`
}

type sessionCache interface {
	Get(ctx context.Context, key string) (*sessionEntry, bool)
	Set(ctx context.Context, key string, value *sessionEntry) error
	Remove(ctx context.Context, key string) error
}
