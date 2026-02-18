package oidc

import (
	"context"
	"time"

	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
)

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
}

type Handler struct {
	Options      *Options
	Provider     *oidc.Provider
	OAuth2Config *oauth2.Config
	Verifier     *oidc.IDTokenVerifier
	SessionStore *SessionStore
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
