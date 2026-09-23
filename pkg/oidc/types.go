package oidc

import (
	"net/http"
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

// ClaimMapper extracts standard session fields from raw ID token claims.
// Returns name, username, and email extracted from the claims map.
// If nil on a ProviderOptions, the DefaultClaimMapper is used.
type ClaimMapper func(claims map[string]interface{}) (name, username, email string)

type Options struct {
	// OIDC provider configuration
	Provider *ProviderOptions
	// Session configuration
	// Used to create a new SessionStore if ExternalSessionStore is nil
	Session *SessionOptions
	// ExternalSessionStore allows injecting a shared session store (used by MultiHandler).
	// If non-nil, the Session field is ignored and this store is used directly.
	ExternalSessionStore *SessionStore
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
	// DisableIframeLogoutDetection stops the shared logout route from treating a
	// Sec-Fetch-Dest: iframe request without iss/sid as a front-channel logout. Set it
	// when the application itself runs inside an iframe (a logout click would otherwise
	// skip the provider logout) and register <base>/frontchannel-logout at the provider.
	DisableIframeLogoutDetection bool
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
	// AccessTokenVerifier verifies access tokens with the same realm keys as
	// the ID token but without the audience check — see parseAccessTokenClaims.
	AccessTokenVerifier *oidc.IDTokenVerifier
	SessionStore        *SessionStore
	gocloak             *gocloakClient
}

type SessionStore struct {
	Options       *SessionOptions
	store         sessions.Store
	backend       SessionBackend
	encryptionKey []byte
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
	// SameSite attribute of the session cookie. Zero leaves it unset (browser default, Lax).
	// OIDC front-channel logout calls the RP's logout URI from an iframe on the provider's
	// page; that request only carries the cookie with http.SameSiteNoneMode (needs Secure).
	SameSite http.SameSite
	// Backend stores the server-side session state (login state, session data, flash).
	// Share one backend between replicas; see SessionBackend for what it must guarantee.
	// If nil, Redis is used when configured, otherwise an in-process store that only
	// works for a single replica. Mutually exclusive with Redis.
	Backend SessionBackend
	// max number of sessions the in-process store keeps
	// defaults to 10000
	CacheSize int
	// TTL for sessions in the in-process store
	// defaults to MaxAge duration
	CacheTTL time.Duration
	// Redis configuration for distributed sessions
	// if nil (and Backend is nil), uses the in-process store (default)
	Redis *RedisSessionOptions
}

type RedisSessionOptions struct {
	Host     string
	Port     int
	Password string
	DB       int
	// defaults to "oidc-sessions"
	KeyPrefix string
	// Deprecated: ignored since v0.9.0, values live for the session's MaxAge.
	TTL time.Duration
	// Deprecated: ignored since v0.9.0, there is no local cache in front of Redis.
	PubSub bool
	// Deprecated: ignored since v0.9.0.
	PubSubChannelName string
	// Deprecated: ignored since v0.9.0.
	LocalTTL time.Duration
	// Deprecated: ignored since v0.9.0.
	RemoteAsync bool
	// Deprecated: ignored since v0.9.0.
	Preload bool
}

type ProviderOptions struct {
	// Human-readable provider name used in routes and SessionData.Provider.
	// e.g., "oidc", "google", "microsoft"
	// If empty, defaults to "oidc"
	Name string
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
	// ClaimMapper extracts name, username, and email from the raw ID token claims.
	// If nil, DefaultClaimMapper is used (reads "name", "preferred_username", "email").
	ClaimMapper ClaimMapper
}

type SessionData struct {
	Authenticated bool
	Provider      string
	Sub           string
	Name          string
	Username      string
	Email         string
	// IDToken is the raw ID token, sent as id_token_hint on RP-initiated logout.
	IDToken string
	// Claims are the ID token's claims.
	Claims map[string]interface{}
	// AccessTokenClaims are the access token's claims, empty when the provider
	// issues an opaque access token. This is where keycloak puts roles and
	// groups unless the ID token mappers were switched on by hand.
	AccessTokenClaims map[string]interface{}
	RealmRoles        []string
	ClientRoles       []string
	Groups            []string
	Attributes        map[string][]string
}
