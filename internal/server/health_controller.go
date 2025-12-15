package server

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func (s *Server) registerHealthRoute() error {
	s.Engine.GET(fmt.Sprintf("%s/health", s.Options.ApiBaseUrl), s.getHealthHandler())
	return nil
}

func (s *Server) getHealthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	}
}
