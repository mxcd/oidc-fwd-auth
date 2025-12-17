package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mxcd/oidc-fwd-auth/pkg/jwt"
	"github.com/mxcd/oidc-fwd-auth/pkg/oidc"
	"github.com/rs/zerolog/log"
)

func (s *Server) registerFwdAuthRoutes() error {
	s.Engine.GET(s.Options.FwdAuthApiEndpoint, s.handleApiAuth())
	s.Engine.GET(s.Options.FwdAuthUiEndpoint, s.handleUiAuth())
	return nil
}

func (s *Server) handleApiAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session data from OIDC handler
		sessionData, err := s.Options.OidcHandler.SessionStore.GetSessionData(c.Request)
		if err != nil || sessionData == nil || !sessionData.Authenticated {
			log.Debug().Msg("no valid session found for API auth, rejecting with 401")
			// API auth rejects immediately with 401
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		s.setAuthHeaderAndRespond(c, sessionData)
	}
}

func (s *Server) handleUiAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session data from OIDC handler
		sessionData, err := s.Options.OidcHandler.SessionStore.GetSessionData(c.Request)
		if err != nil || sessionData == nil || !sessionData.Authenticated {
			log.Debug().Msg("no valid session found for UI auth, redirecting to login")
			// UI auth redirects to login page
			// Save the original URL to redirect back after login
			originalURL := c.Request.Header.Get("X-Original-URL")
			if originalURL == "" {
				originalURL = c.Request.URL.String()
			}

			// Store the original URL in session flash for redirect after login
			err := s.Options.OidcHandler.SessionStore.SetStringFlash(c.Request, c.Writer, originalURL)
			if err != nil {
				log.Error().Err(err).Msg("failed to set flash message")
			}

			// Redirect to login
			loginURL := s.Options.OidcHandler.Options.AuthBaseUrl + s.Options.OidcHandler.Options.AuthBaseContextPath + "/login"
			c.Redirect(http.StatusFound, loginURL)
			return
		}

		s.setAuthHeaderAndRespond(c, sessionData)
	}
}

func (s *Server) setAuthHeaderAndRespond(c *gin.Context, sessionData *oidc.SessionData) {

	// Create JWT token with session data
	token := jwt.NewToken()
	token.Subject = sessionData.Sub
	token.Issuer = s.Options.JwtSigner.Options.JwtIssuer

	// Add all OIDC claims to the JWT
	for k, v := range sessionData.Claims {
		token.Claims[k] = v
	}

	// Convert to jwx token and sign
	jwxToken := token.ToJWT()
	signedToken, err := s.Options.JwtSigner.SignToken(jwxToken)
	if err != nil {
		log.Error().Err(err).Msg("failed to sign JWT token")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	// Add JWT to Authorization header
	c.Header("Authorization", "Bearer "+string(signedToken))

	// Continue to next handler (or return success)
	c.JSON(http.StatusOK, gin.H{"status": "authenticated"})
}
