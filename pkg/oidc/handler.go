package oidc

import (
	"context"
	"encoding/gob"
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

	gob.Register(SessionData{})

	return handler, nil
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

	return nil
}
