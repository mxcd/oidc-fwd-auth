package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/mxcd/oidc-fwd-auth/pkg/jwt"
	"github.com/mxcd/oidc-fwd-auth/pkg/oidc"
	"github.com/rs/zerolog/log"
)

type ServerOptions struct {
	ServiceVersion     string
	DevMode            bool
	Port               int
	HealthEndpoint     string
	FwdAuthApiEndpoint string
	FwdAuthUiEndpoint  string
	JwksEndpoint       string
	LogoutRedirectUrl  string
	OidcHandler        *oidc.Handler
	JwtSigner          *jwt.Signer
}

type Server struct {
	Options    *ServerOptions
	Engine     *gin.Engine
	HttpServer *http.Server
}

func NewServer(options *ServerOptions) (*Server, error) {
	if options == nil {
		return nil, fmt.Errorf("server options cannot be nil")
	}

	server := &Server{
		Options: options,
	}

	if !server.Options.DevMode {
		log.Info().Msg("Running Gin in production mode")
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()

	server.Engine = engine
	server.Engine.Use(gin.Recovery(), server.zeroLogger())
	server.HttpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", options.Port),
		Handler: engine,
	}

	if server.Options.DevMode {
		log.Info().Msg("Running Gin in development mode")
		log.Warn().Msg("CORS is enabled for all origins")
		config := cors.DefaultConfig()
		config.AllowHeaders = []string{"Authorization", "Content-Type", "X-Requested-With", "X-PINGOTHER", "X-File-Name", "Cache-Control"}
		config.AllowOrigins = []string{"http://localhost:8080"}
		config.AllowCredentials = true
		server.Engine.Use(cors.New(config))
	}

	return server, nil
}

func (s *Server) RegisterRoutes() error {
	s.registerHealthRoute()
	s.registerJwksRoute()
	s.Options.OidcHandler.RegisterRoutes(s.Engine)
	s.registerFwdAuthRoutes()

	return nil
}

func (s *Server) Run() error {
	if err := s.HttpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) {
	s.HttpServer.Shutdown(ctx)
}

func (s *Server) zeroLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		c.Next()

		status := c.Writer.Status()
		latency := time.Since(start)

		logger := log.Trace()

		logger.
			Str("method", method).
			Str("path", path).
			Int("status", status).
			Str("client_ip", c.ClientIP()).
			Str("latency", latency.String()).
			Msg("http_request")
	}
}
