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

// getSessionStore returns the session store from either the multi-handler or the single handler.
func (s *Server) getSessionStore() *oidc.SessionStore {
	if s.Options.MultiHandler != nil {
		return s.Options.MultiHandler.SessionStore
	}
	return s.Options.OidcHandler.SessionStore
}

// getLoginURL returns the login URL for UI auth redirects.
func (s *Server) getLoginURL() string {
	if s.Options.MultiHandler != nil {
		return s.Options.MultiHandler.LoginURL()
	}
	return s.Options.OidcHandler.Options.AuthBaseUrl + s.Options.OidcHandler.Options.AuthBaseContextPath + "/login"
}

func (s *Server) handleApiAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionData, err := s.getSessionStore().GetSessionData(c.Request)
		if err != nil || sessionData == nil || !sessionData.Authenticated {
			log.Debug().Msg("no valid session found for API auth, rejecting with 401")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		s.setAuthHeaderAndRespond(c, sessionData)
	}
}

func (s *Server) handleUiAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionData, err := s.getSessionStore().GetSessionData(c.Request)
		if err != nil || sessionData == nil || !sessionData.Authenticated {
			log.Debug().Msg("no valid session found for UI auth, redirecting to login")
			originalURL := c.Request.Header.Get("X-Original-URL")
			if originalURL == "" {
				originalURL = c.Request.URL.String()
			}

			err := s.getSessionStore().SetStringFlash(c.Request, c.Writer, originalURL)
			if err != nil {
				log.Error().Err(err).Msg("failed to set flash message")
			}

			loginURL := s.getLoginURL()
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

	if sessionData.Provider != "" {
		token.Claims["provider"] = sessionData.Provider
	}
	if len(sessionData.RealmRoles) > 0 {
		token.Claims["realm_roles"] = sessionData.RealmRoles
	}
	if len(sessionData.ClientRoles) > 0 {
		token.Claims["client_roles"] = sessionData.ClientRoles
	}
	if len(sessionData.Groups) > 0 {
		token.Claims["groups"] = sessionData.Groups
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
