package oidc

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func NewHandler(options *Options) (*Handler, error) {
	err := validateOptions(options)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, options.Provider.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	if len(options.Provider.Scopes) == 0 {
		options.Provider.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	options.Provider.Scopes = mergeScopes(options.Provider.Scopes, options.Provider.ExtraScopes)

	if options.AuthBaseContextPath == "" {
		options.AuthBaseContextPath = "/auth/oidc"
	}

	oauth2Config := &oauth2.Config{
		ClientID:     options.Provider.ClientId,
		ClientSecret: options.Provider.ClientSecret,
		RedirectURL:  options.Provider.RedirectUri,
		Endpoint:     provider.Endpoint(),
		Scopes:       options.Provider.Scopes,
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: options.Provider.ClientId,
	})

	sessionStore, err := newSessionStore(options.Session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session store: %w", err)
	}

	handler := &Handler{
		Options:      options,
		Provider:     provider,
		OAuth2Config: oauth2Config,
		Verifier:     verifier,
		SessionStore: sessionStore,
	}

	if options.Gocloak != nil {
		gc, err := newGocloakClient(options.Gocloak)
		if err != nil {
			return nil, fmt.Errorf("failed to create gocloak client: %w", err)
		}
		handler.gocloak = gc
	}

	return handler, nil
}

// FetchUserAuthorization fetches realm roles, client roles, and groups for a user
// from the Keycloak Admin API via Gocloak. Returns an error if Gocloak is not configured.
// The userID parameter is the Keycloak user UUID (typically idToken.Subject).
func (h *Handler) FetchUserAuthorization(ctx context.Context, userID string) (realmRoles, clientRoles, groups []string, err error) {
	if h.gocloak == nil {
		return nil, nil, nil, fmt.Errorf("gocloak is not configured")
	}
	return h.gocloak.FetchUserAuthorization(ctx, userID)
}

// GocloakEnabled returns true if the Gocloak integration is configured and available.
func (h *Handler) GocloakEnabled() bool {
	return h.gocloak != nil
}

func validateOptions(options *Options) error {
	if options == nil {
		return fmt.Errorf("options cannot be nil")
	}

	if options.Provider.ClientId == "" {
		return fmt.Errorf("provider client ID cannot be empty")
	}
	if options.Provider.ClientSecret == "" {
		return fmt.Errorf("provider client secret cannot be empty")
	}
	if options.Provider.Issuer == "" {
		return fmt.Errorf("provider issuer cannot be empty")
	}
	if options.Provider.RedirectUri == "" {
		return fmt.Errorf("provider redirect URI cannot be empty")
	}

	if options.Session.SecretSigningKey == "" {
		return fmt.Errorf("session secret signing key cannot be empty")
	}
	if len(options.Session.SecretEncryptionKey) != 32 && len(options.Session.SecretEncryptionKey) != 64 {
		return fmt.Errorf("session secret encryption key must be 32 or 64 bytes long")
	}
	if options.Session.Name == "" {
		return fmt.Errorf("session name cannot be empty")
	}

	if options.Session.Redis != nil && options.Session.Redis.Host == "" {
		return fmt.Errorf("redis host cannot be empty when Redis is enabled")
	}

	return nil
}
