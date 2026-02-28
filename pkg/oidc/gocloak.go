package oidc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/rs/zerolog/log"
)

type AuthorizationDeniedError struct {
	Missing string
}

func (e *AuthorizationDeniedError) Error() string {
	return fmt.Sprintf("authorization denied: missing %s", e.Missing)
}

type gocloakClient struct {
	client          *gocloak.GoCloak
	opts            *GocloakOptions
	token           string
	tokenExpiry     time.Time
	tokenMu         sync.Mutex
	clientUUID      string
	clientUUIDOnce  sync.Once
	clientUUIDErr   error
}

func newGocloakClient(opts *GocloakOptions) (*gocloakClient, error) {
	if opts.ServerURL == "" {
		return nil, fmt.Errorf("gocloak server URL cannot be empty")
	}
	if opts.Realm == "" {
		return nil, fmt.Errorf("gocloak realm cannot be empty")
	}
	if opts.AuthMethod == "" {
		opts.AuthMethod = "password"
	}
	if opts.AuthMethod != "password" && opts.AuthMethod != "client_credentials" {
		return nil, fmt.Errorf("gocloak auth method must be 'password' or 'client_credentials'")
	}
	if opts.AuthMethod == "password" {
		if opts.Username == "" || opts.Password == "" {
			return nil, fmt.Errorf("gocloak username and password are required for password auth")
		}
	}
	if opts.AuthMethod == "client_credentials" {
		if opts.ClientID == "" || opts.ClientSecret == "" {
			return nil, fmt.Errorf("gocloak client ID and secret are required for client_credentials auth")
		}
	}

	client := gocloak.NewClient(opts.ServerURL)

	return &gocloakClient{
		client: client,
		opts:   opts,
	}, nil
}

func (g *gocloakClient) getToken(ctx context.Context) (string, error) {
	g.tokenMu.Lock()
	defer g.tokenMu.Unlock()

	if g.token != "" && time.Now().Before(g.tokenExpiry.Add(-30*time.Second)) {
		return g.token, nil
	}

	var jwt *gocloak.JWT
	var err error

	if g.opts.AuthMethod == "client_credentials" {
		jwt, err = g.client.LoginClient(ctx, g.opts.ClientID, g.opts.ClientSecret, g.opts.Realm)
	} else {
		jwt, err = g.client.LoginAdmin(ctx, g.opts.Username, g.opts.Password, g.opts.Realm)
	}
	if err != nil {
		return "", fmt.Errorf("failed to authenticate to Keycloak: %w", err)
	}

	g.token = jwt.AccessToken
	g.tokenExpiry = time.Now().Add(time.Duration(jwt.ExpiresIn) * time.Second)
	return g.token, nil
}

func (g *gocloakClient) resolveClientUUID(ctx context.Context, accessToken string) (string, error) {
	g.clientUUIDOnce.Do(func() {
		clients, err := g.client.GetClients(ctx, accessToken, g.opts.Realm, gocloak.GetClientsParams{
			ClientID: gocloak.StringP(g.opts.ClientRolesClientID),
		})
		if err != nil {
			g.clientUUIDErr = fmt.Errorf("failed to resolve client UUID: %w", err)
			return
		}
		if len(clients) == 0 {
			g.clientUUIDErr = fmt.Errorf("client '%s' not found in realm '%s'", g.opts.ClientRolesClientID, g.opts.Realm)
			return
		}
		g.clientUUID = *clients[0].ID
	})
	return g.clientUUID, g.clientUUIDErr
}

func (g *gocloakClient) FetchUserAuthorization(ctx context.Context, userID string) (realmRoles, clientRoles, groups []string, attributes map[string][]string, err error) {
	accessToken, err := g.getToken(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Fetch realm roles (composite includes roles inherited through groups)
	realmRoleMappings, err := g.client.GetCompositeRealmRolesByUserID(ctx, accessToken, g.opts.Realm, userID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to get realm roles: %w", err)
	}
	for _, role := range realmRoleMappings {
		if role.Name != nil {
			realmRoles = append(realmRoles, *role.Name)
		}
	}

	// Fetch client roles if configured
	if g.opts.ClientRolesClientID != "" {
		clientUUID, err := g.resolveClientUUID(ctx, accessToken)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		clientRoleMappings, err := g.client.GetCompositeClientRolesByUserID(ctx, accessToken, g.opts.Realm, clientUUID, userID)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to get client roles: %w", err)
		}
		for _, role := range clientRoleMappings {
			if role.Name != nil {
				clientRoles = append(clientRoles, *role.Name)
			}
		}
	}

	// Fetch groups
	userGroups, err := g.client.GetUserGroups(ctx, accessToken, g.opts.Realm, userID, gocloak.GetGroupsParams{})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to get user groups: %w", err)
	}
	for _, group := range userGroups {
		if group.Path != nil {
			groups = append(groups, *group.Path)
		}
	}

	// Fetch user attributes
	user, err := g.client.GetUserByID(ctx, accessToken, g.opts.Realm, userID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to get user attributes: %w", err)
	}
	if user.Attributes != nil {
		attributes = *user.Attributes
	}

	// Check required realm roles
	if len(g.opts.RequiredRealmRoles) > 0 {
		userRealmRoleSet := toSet(realmRoles)
		for _, required := range g.opts.RequiredRealmRoles {
			if !userRealmRoleSet[required] {
				log.Warn().Str("role", required).Str("user", userID).Msg("user missing required realm role")
				return nil, nil, nil, nil, &AuthorizationDeniedError{Missing: fmt.Sprintf("realm role '%s'", required)}
			}
		}
	}

	// Check required client roles
	if len(g.opts.RequiredClientRoles) > 0 {
		userClientRoleSet := toSet(clientRoles)
		for _, required := range g.opts.RequiredClientRoles {
			if !userClientRoleSet[required] {
				log.Warn().Str("role", required).Str("user", userID).Msg("user missing required client role")
				return nil, nil, nil, nil, &AuthorizationDeniedError{Missing: fmt.Sprintf("client role '%s'", required)}
			}
		}
	}

	// Check required groups
	if len(g.opts.RequiredGroups) > 0 {
		userGroupSet := toSet(groups)
		for _, required := range g.opts.RequiredGroups {
			if !userGroupSet[required] {
				log.Warn().Str("group", required).Str("user", userID).Msg("user missing required group")
				return nil, nil, nil, nil, &AuthorizationDeniedError{Missing: fmt.Sprintf("group '%s'", required)}
			}
		}
	}

	return realmRoles, clientRoles, groups, attributes, nil
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[item] = true
	}
	return s
}
