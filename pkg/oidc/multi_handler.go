package oidc

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// MultiHandlerOptions configures a MultiHandler that manages multiple OIDC providers.
type MultiHandlerOptions struct {
	// Session configuration shared across all providers.
	Session *SessionOptions
	// DefaultProvider is the provider name to use for UI auth redirects.
	// If empty and only one provider is registered, that provider is used automatically.
	DefaultProvider string
	// LoginSelectorUrl is the URL to redirect to when no default provider is set
	// and multiple providers exist. This page should present the user with provider choices
	// (e.g., linking to /auth/oidc/login, /auth/google/login, etc.).
	LoginSelectorUrl string
	// AuthBaseUrl is the base URL for constructing login redirect URLs (e.g., "http://localhost:8080").
	AuthBaseUrl string
}

// MultiHandler manages multiple OIDC providers sharing a single session store.
// Use this when you want to offer multiple login options (e.g., Keycloak + Google).
type MultiHandler struct {
	Options      *MultiHandlerOptions
	Handlers     map[string]*Handler
	SessionStore *SessionStore
}

// NewMultiHandler creates a MultiHandler with a shared session store.
func NewMultiHandler(options *MultiHandlerOptions) (*MultiHandler, error) {
	if options == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}
	if options.Session == nil {
		return nil, fmt.Errorf("session options cannot be nil")
	}

	sessionStore, err := newSessionStore(options.Session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session store: %w", err)
	}

	return &MultiHandler{
		Options:      options,
		Handlers:     make(map[string]*Handler),
		SessionStore: sessionStore,
	}, nil
}

// AddProvider creates and registers a new OIDC provider handler.
// The provider's Name field in ProviderOptions determines the key and route prefix.
// The shared session store is automatically injected.
func (m *MultiHandler) AddProvider(opts *Options) error {
	if opts.Provider.Name == "" {
		opts.Provider.Name = "oidc"
	}
	if _, exists := m.Handlers[opts.Provider.Name]; exists {
		return fmt.Errorf("provider %q already registered", opts.Provider.Name)
	}

	// Inject shared session store
	opts.ExternalSessionStore = m.SessionStore

	handler, err := NewHandler(opts)
	if err != nil {
		return fmt.Errorf("failed to create handler for provider %q: %w", opts.Provider.Name, err)
	}

	m.Handlers[opts.Provider.Name] = handler
	return nil
}

// RegisterRoutes registers all provider routes on the Gin engine.
func (m *MultiHandler) RegisterRoutes(engine *gin.Engine) {
	for _, handler := range m.Handlers {
		handler.RegisterRoutes(engine)
	}
}

// GetHandler returns the handler for a specific provider name.
func (m *MultiHandler) GetHandler(name string) (*Handler, bool) {
	h, ok := m.Handlers[name]
	return h, ok
}

// GetDefaultHandler returns the handler to use for UI auth redirects.
// Returns the explicitly configured default, or the only registered provider,
// or nil if no default can be determined.
func (m *MultiHandler) GetDefaultHandler() *Handler {
	if m.Options.DefaultProvider != "" {
		if h, ok := m.Handlers[m.Options.DefaultProvider]; ok {
			return h
		}
	}
	if len(m.Handlers) == 1 {
		for _, h := range m.Handlers {
			return h
		}
	}
	return nil
}

// LoginURL returns the login URL for UI auth redirects.
// If a default provider exists, returns its login URL.
// If a LoginSelectorUrl is configured, returns that.
// Falls back to the "oidc" provider if registered, then "/login".
func (m *MultiHandler) LoginURL() string {
	if h := m.GetDefaultHandler(); h != nil {
		return h.Options.AuthBaseUrl + h.Options.AuthBaseContextPath + "/login"
	}
	if m.Options.LoginSelectorUrl != "" {
		return m.Options.LoginSelectorUrl
	}
	if h, ok := m.Handlers["oidc"]; ok {
		return h.Options.AuthBaseUrl + h.Options.AuthBaseContextPath + "/login"
	}
	return "/login"
}

// ProviderNames returns a list of registered provider names.
func (m *MultiHandler) ProviderNames() []string {
	names := make([]string, 0, len(m.Handlers))
	for name := range m.Handlers {
		names = append(names, name)
	}
	return names
}

// GetUiAuthMiddleware returns a Gin middleware that checks for an authenticated session
// and redirects to the appropriate login URL if not authenticated.
func (m *MultiHandler) GetUiAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionData, err := m.SessionStore.GetSessionData(c.Request)
		if err != nil || sessionData == nil || !sessionData.Authenticated {
			_ = m.SessionStore.SetStringFlash(c.Request, c.Writer, c.Request.URL.Path)
			c.Redirect(302, m.LoginURL())
			c.Abort()
			return
		}
		c.Set("sessionData", sessionData)
		c.Set("realmRoles", sessionData.RealmRoles)
		c.Set("clientRoles", sessionData.ClientRoles)
		c.Set("groups", sessionData.Groups)
		c.Set("attributes", sessionData.Attributes)
		c.Set("provider", sessionData.Provider)
		c.Next()
	}
}

// GetApiAuthMiddleware returns a Gin middleware that checks for an authenticated session
// and returns 401 if not authenticated.
func (m *MultiHandler) GetApiAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionData, err := m.SessionStore.GetSessionData(c.Request)
		if err != nil || sessionData == nil || !sessionData.Authenticated {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("sessionData", sessionData)
		c.Set("realmRoles", sessionData.RealmRoles)
		c.Set("clientRoles", sessionData.ClientRoles)
		c.Set("groups", sessionData.Groups)
		c.Set("attributes", sessionData.Attributes)
		c.Set("provider", sessionData.Provider)
		c.Next()
	}
}
