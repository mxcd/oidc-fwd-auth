package main

import (
	"github.com/rs/zerolog/log"

	"github.com/mxcd/go-config/config"
	"github.com/mxcd/oidc-fwd-auth/internal/server"
	"github.com/mxcd/oidc-fwd-auth/internal/util"
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

	server := initServer(&InitServerOptions{
		OIDCHandler: oidcHandler,
	})

	err := server.Run()
	if err != nil {
		log.Panic().Err(err).Msg("error running server")
	}
}

type InitServerOptions struct {
	OIDCHandler *oidc.Handler
}

func initServer(options *InitServerOptions) *server.Server {
	server, err := server.NewServer(&server.ServerOptions{
		ServiceVersion: config.Get().String("DEPLOYMENT_IMAGE_TAG"),
		DevMode:        config.Get().Bool("DEV"),
		Port:           config.Get().Int("PORT"),
		ApiBaseUrl:     config.Get().String("API_BASE_URL"),

		OIDCHandler: options.OIDCHandler,
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
	oidcHandler, err := oidc.NewHandler(&oidc.Options{
		Provider: &oidc.ProviderOptions{
			Issuer:       config.Get().String("OIDC_WELL_KNOWN_URL"),
			ClientId:     config.Get().String("OIDC_CLIENT_ID"),
			ClientSecret: config.Get().String("OIDC_CLIENT_SECRET"),
			RedirectUri:  config.Get().String("OIDC_REDIRECT_URI"),
			LogoutUri:    config.Get().String("OIDC_LOGOUT_URL"),
			Scopes:       []string{"openid", "profile", "email"},
		},
		Session: &oidc.SessionOptions{
			SecretSigningKey:    config.Get().String("SESSION_SIGNING_KEY"),
			SecretEncryptionKey: config.Get().String("SESSION_ENCRYPTION_KEY"),
			Name:                config.Get().String("SESSION_NAME"),
			Domain:              config.Get().String("SESSION_DOMAIN"),
			MaxAge:              config.Get().Int("SESSION_MAX_AGE"),
			Secure:              config.Get().Bool("SESSION_SECURE"),
		},
		AuthBaseUrl:            config.Get().String("API_BASE_URL"),
		EnableUserInfoEndpoint: config.Get().Bool("ENABLE_USERINFO_ENDPOINT"),
	})
	if err != nil {
		log.Panic().Err(err).Msg("error initializing OIDC authenticator")
	}
	return oidcHandler
}
