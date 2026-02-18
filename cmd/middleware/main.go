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
	// ctx := context.Background()

	if err := util.InitConfig(); err != nil {
		log.Panic().Err(err).Msg("error initializing config")
	}
	config.Print()

	if err := util.InitLogger(); err != nil {
		log.Panic().Err(err).Msg("error initializing logger")
	}

	oidcHandler := initOidcHandler()
	jwtSigner := initJwtSigner()

	server := initServer(&InitServerOptions{
		OidcHandler: oidcHandler,
		JwtSigner:   jwtSigner,
	})

	err := server.Run()
	if err != nil {
		log.Panic().Err(err).Msg("error running server")
	}
}

type InitServerOptions struct {
	OidcHandler *oidc.Handler
	JwtSigner   *jwt.Signer
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

func initServer(options *InitServerOptions) *server.Server {
	server, err := server.NewServer(&server.ServerOptions{
		ServiceVersion:     config.Get().String("DEPLOYMENT_IMAGE_TAG"),
		DevMode:            config.Get().Bool("DEV"),
		Port:               config.Get().Int("PORT"),
		HealthEndpoint:     config.Get().String("HEALTH_ENDPOINT"),
		FwdAuthApiEndpoint: config.Get().String("FWD_AUTH_API_ENDPOINT"),
		FwdAuthUiEndpoint:  config.Get().String("FWD_AUTH_UI_ENDPOINT"),
		JwksEndpoint:       config.Get().String("JWKS_ENDPOINT"),

		OidcHandler: options.OidcHandler,
		JwtSigner:   options.JwtSigner,
	})
	if err != nil {
		log.Panic().Err(err).Msg("error initializing server")
	}

	err = server.RegisterRoutes()
	if err != nil {
		log.Panic().Err(err).Msg("error registering routes")
	}

	return server
}

func initOidcHandler() *oidc.Handler {
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

	oidcHandler, err := oidc.NewHandler(&oidc.Options{
		Provider: &oidc.ProviderOptions{
			Issuer:       config.Get().String("OIDC_WELL_KNOWN_URL"),
			ClientId:     config.Get().String("OIDC_CLIENT_ID"),
			ClientSecret: config.Get().String("OIDC_CLIENT_SECRET"),
			RedirectUri:  config.Get().String("OIDC_REDIRECT_URI"),
			LogoutUri:    config.Get().String("OIDC_LOGOUT_URL"),
			Scopes:       config.Get().StringArray("OIDC_SCOPES"),
		},
		Session:                sessionOpts,
		AuthBaseUrl:            config.Get().String("OIDC_ENDPOINTS_BASE_URL"),
		AuthBaseContextPath:    config.Get().String("OIDC_ENDPOINTS_BASE_CONTEXT_PATH"),
		EnableUserInfoEndpoint: config.Get().Bool("ENABLE_USERINFO_ENDPOINT"),
	})
	if err != nil {
		log.Panic().Err(err).Msg("error initializing OIDC authenticator")
	}
	return oidcHandler
}
