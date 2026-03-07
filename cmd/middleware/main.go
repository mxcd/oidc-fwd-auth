package main

import (
	"github.com/rs/zerolog/log"

	"github.com/mxcd/go-config/config"
	"github.com/mxcd/oidc-fwd-auth/internal/server"
	"github.com/mxcd/oidc-fwd-auth/internal/util"
	"github.com/mxcd/oidc-fwd-auth/pkg/jwt"
	"github.com/mxcd/oidc-fwd-auth/pkg/oidc"
)

func main() {
	if err := util.InitConfig(); err != nil {
		log.Panic().Err(err).Msg("error initializing config")
	}
	config.Print()

	if err := util.InitLogger(); err != nil {
		log.Panic().Err(err).Msg("error initializing logger")
	}

	jwtSigner := initJwtSigner()

	if config.Get().Bool("GOOGLE_ENABLED") {
		// Multi-provider mode: one or more social providers enabled alongside generic OIDC
		multiHandler := initMultiHandler()
		srv := initServerWithMultiHandler(multiHandler, jwtSigner)
		if err := srv.Run(); err != nil {
			log.Panic().Err(err).Msg("error running server")
		}
	} else {
		// Legacy single-provider mode (unchanged behavior)
		oidcHandler := initOidcHandler()
		srv := initServer(oidcHandler, jwtSigner)
		if err := srv.Run(); err != nil {
			log.Panic().Err(err).Msg("error running server")
		}
	}
}

func initJwtSigner() *jwt.Signer {
	signer, err := jwt.NewSigner(&jwt.SignerOptions{
		Algorithm:     "RS512",
		JwtIssuer:     config.Get().String("JWT_ISSUER"),
		JwtPrivateKey: config.Get().String("JWT_PRIVATE_KEY"),
	})
	if err != nil {
		log.Panic().Err(err).Msg("error initializing JWT signer")
	}
	return signer
}

func newServerOptions(jwtSigner *jwt.Signer) *server.ServerOptions {
	return &server.ServerOptions{
		ServiceVersion:     config.Get().String("DEPLOYMENT_IMAGE_TAG"),
		DevMode:            config.Get().Bool("DEV"),
		Port:               config.Get().Int("PORT"),
		HealthEndpoint:     config.Get().String("HEALTH_ENDPOINT"),
		FwdAuthApiEndpoint: config.Get().String("FWD_AUTH_API_ENDPOINT"),
		FwdAuthUiEndpoint:  config.Get().String("FWD_AUTH_UI_ENDPOINT"),
		JwksEndpoint:       config.Get().String("JWKS_ENDPOINT"),
		JwtSigner:          jwtSigner,
	}
}

func initServer(oidcHandler *oidc.Handler, jwtSigner *jwt.Signer) *server.Server {
	opts := newServerOptions(jwtSigner)
	opts.OidcHandler = oidcHandler

	srv, err := server.NewServer(opts)
	if err != nil {
		log.Panic().Err(err).Msg("error initializing server")
	}
	if err = srv.RegisterRoutes(); err != nil {
		log.Panic().Err(err).Msg("error registering routes")
	}
	return srv
}

func initServerWithMultiHandler(multiHandler *oidc.MultiHandler, jwtSigner *jwt.Signer) *server.Server {
	opts := newServerOptions(jwtSigner)
	opts.MultiHandler = multiHandler

	srv, err := server.NewServer(opts)
	if err != nil {
		log.Panic().Err(err).Msg("error initializing server")
	}
	if err = srv.RegisterRoutes(); err != nil {
		log.Panic().Err(err).Msg("error registering routes")
	}
	return srv
}

func buildSessionOpts() *oidc.SessionOptions {
	sessionOpts := &oidc.SessionOptions{
		SecretSigningKey:    config.Get().String("SESSION_SIGNING_KEY"),
		SecretEncryptionKey: config.Get().String("SESSION_ENCRYPTION_KEY"),
		Name:                config.Get().String("SESSION_NAME"),
		Domain:              config.Get().String("SESSION_DOMAIN"),
		MaxAge:              config.Get().Int("SESSION_MAX_AGE"),
		Secure:              config.Get().Bool("SESSION_SECURE"),
		CacheSize:           config.Get().Int("SESSION_CACHE_SIZE"),
	}

	if config.Get().Bool("SESSION_REDIS_ENABLED") {
		sessionOpts.Redis = &oidc.RedisSessionOptions{
			Host:              config.Get().String("SESSION_REDIS_HOST"),
			Port:              config.Get().Int("SESSION_REDIS_PORT"),
			Password:          config.Get().String("SESSION_REDIS_PASSWORD"),
			DB:                config.Get().Int("SESSION_REDIS_DB"),
			KeyPrefix:         config.Get().String("SESSION_REDIS_KEY_PREFIX"),
			PubSub:            config.Get().Bool("SESSION_REDIS_PUBSUB"),
			PubSubChannelName: config.Get().String("SESSION_REDIS_PUBSUB_CHANNEL"),
			RemoteAsync:       config.Get().Bool("SESSION_REDIS_REMOTE_ASYNC"),
			Preload:           config.Get().Bool("SESSION_REDIS_PRELOAD"),
		}
	}

	return sessionOpts
}

func buildOidcProviderOpts() *oidc.Options {
	oidcOpts := &oidc.Options{
		Provider: &oidc.ProviderOptions{
			Name:         "oidc",
			Issuer:       config.Get().String("OIDC_WELL_KNOWN_URL"),
			ClientId:     config.Get().String("OIDC_CLIENT_ID"),
			ClientSecret: config.Get().String("OIDC_CLIENT_SECRET"),
			RedirectUri:  config.Get().String("OIDC_REDIRECT_URI"),
			LogoutUri:    config.Get().String("OIDC_LOGOUT_URL"),
			Scopes:       config.Get().StringArray("OIDC_SCOPES"),
		},
		AuthBaseUrl:            config.Get().String("OIDC_ENDPOINTS_BASE_URL"),
		AuthBaseContextPath:    config.Get().String("OIDC_ENDPOINTS_BASE_CONTEXT_PATH"),
		EnableUserInfoEndpoint: config.Get().Bool("ENABLE_USERINFO_ENDPOINT"),
	}

	if config.Get().Bool("KEYCLOAK_ENABLED") {
		oidcOpts.Gocloak = &oidc.GocloakOptions{
			ServerURL:           config.Get().String("KEYCLOAK_SERVER_URL"),
			Realm:               config.Get().String("KEYCLOAK_REALM"),
			AuthMethod:          config.Get().String("KEYCLOAK_AUTH_METHOD"),
			Username:            config.Get().String("KEYCLOAK_USERNAME"),
			Password:            config.Get().String("KEYCLOAK_PASSWORD"),
			ClientID:            config.Get().String("KEYCLOAK_CLIENT_ID"),
			ClientSecret:        config.Get().String("KEYCLOAK_CLIENT_SECRET"),
			RequiredRealmRoles:  config.Get().StringArray("KEYCLOAK_REQUIRED_REALM_ROLES"),
			RequiredClientRoles: config.Get().StringArray("KEYCLOAK_REQUIRED_CLIENT_ROLES"),
			ClientRolesClientID: config.Get().String("KEYCLOAK_CLIENT_ROLES_CLIENT_ID"),
			RequiredGroups:      config.Get().StringArray("KEYCLOAK_REQUIRED_GROUPS"),
		}
	}

	return oidcOpts
}

func initOidcHandler() *oidc.Handler {
	oidcOpts := buildOidcProviderOpts()
	oidcOpts.Session = buildSessionOpts()

	oidcHandler, err := oidc.NewHandler(oidcOpts)
	if err != nil {
		log.Panic().Err(err).Msg("error initializing OIDC authenticator")
	}
	return oidcHandler
}

func initMultiHandler() *oidc.MultiHandler {
	multiHandler, err := oidc.NewMultiHandler(&oidc.MultiHandlerOptions{
		Session:          buildSessionOpts(),
		DefaultProvider:  config.Get().String("AUTH_DEFAULT_PROVIDER"),
		LoginSelectorUrl: config.Get().String("AUTH_LOGIN_SELECTOR_URL"),
		AuthBaseUrl:      config.Get().String("OIDC_ENDPOINTS_BASE_URL"),
	})
	if err != nil {
		log.Panic().Err(err).Msg("error initializing multi-handler")
	}

	// Add the primary OIDC provider
	if err := multiHandler.AddProvider(buildOidcProviderOpts()); err != nil {
		log.Panic().Err(err).Msg("error adding OIDC provider")
	}

	// Add Google provider
	googleRedirectURI := config.Get().String("GOOGLE_REDIRECT_URI")
	if googleRedirectURI == "" {
		googleRedirectURI = config.Get().String("OIDC_ENDPOINTS_BASE_URL") + "/auth/google/callback"
	}

	googleOpts := &oidc.Options{
		Provider: &oidc.ProviderOptions{
			Name:         "google",
			Issuer:       "https://accounts.google.com",
			ClientId:     config.Get().String("GOOGLE_CLIENT_ID"),
			ClientSecret: config.Get().String("GOOGLE_CLIENT_SECRET"),
			RedirectUri:  googleRedirectURI,
			Scopes:       config.Get().StringArray("GOOGLE_SCOPES"),
			ClaimMapper:  oidc.GoogleClaimMapper,
		},
		AuthBaseUrl:            config.Get().String("OIDC_ENDPOINTS_BASE_URL"),
		AuthBaseContextPath:    "/auth/google",
		EnableUserInfoEndpoint: config.Get().Bool("ENABLE_USERINFO_ENDPOINT"),
	}

	if err := multiHandler.AddProvider(googleOpts); err != nil {
		log.Panic().Err(err).Msg("error adding Google provider")
	}

	return multiHandler
}
