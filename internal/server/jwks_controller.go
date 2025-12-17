package server

import (
	"github.com/gin-gonic/gin"
)

func (s *Server) registerJwksRoute() error {
	s.Engine.GET(s.Options.JwksEndpoint, s.getJwksHandler())
	return nil
}

func (s *Server) getJwksHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwks := s.Options.JwtSigner.Jwks
		c.JSON(200, jwks)
	}
}
