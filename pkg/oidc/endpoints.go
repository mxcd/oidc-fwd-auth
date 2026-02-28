package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (h *Handler) RegisterRoutes(engine *gin.Engine) {
	engine.GET(h.Options.AuthBaseContextPath+"/login", h.loginHandler())
	engine.GET(h.Options.AuthBaseContextPath+"/callback", h.callbackHandler())
	engine.GET(h.Options.AuthBaseContextPath+"/logout", h.logoutHandler())
	if h.Options.EnableUserInfoEndpoint {
		engine.GET(h.Options.AuthBaseContextPath+"/userinfo", h.GetUiAuthMiddleware(), h.userinfoHandler())
	}
}

func (h *Handler) loginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		state, err := generateSessionState()
		if err != nil {
			log.Error().Err(err).Msg("failed to generate state")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
			return
		}

		err = h.SessionStore.NewSession(c.Request, c.Writer)
		if err != nil {
			log.Error().Err(err).Msg("failed to create new session")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create new session"})
			return
		}

		err = h.SessionStore.SetStringValue(c.Request, c.Writer, "state", state)
		if err != nil {
			log.Error().Err(err).Msg("failed to set state in session")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to set state in session"})
			return
		}

		authURL := h.OAuth2Config.AuthCodeURL(state)
		c.Redirect(http.StatusFound, authURL)
	}
}

func (h *Handler) callbackHandler() gin.HandlerFunc {
	return func(c *gin.Context) {

		state := c.Query("state")
		savedState, err := h.SessionStore.GetStringValue(c.Request, "state")
		if err != nil {
			log.Error().Err(err).Msg("failed to get state from session")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get state from session"})
			return
		}

		if state == "" || savedState == "" || state != savedState {
			log.Warn().Msg("state mismatch in OIDC callback")
			c.JSON(http.StatusBadRequest, gin.H{"error": "state mismatch"})
			return
		}

		code := c.Query("code")
		if code == "" {
			log.Warn().Msg("no code in OIDC callback")
			c.JSON(http.StatusBadRequest, gin.H{"error": "no code provided"})
			return
		}

		ctx := context.Background()
		oauth2Token, err := h.OAuth2Config.Exchange(ctx, code)
		if err != nil {
			log.Error().Err(err).Msg("failed to exchange token")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to exchange token"})
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Error().Msg("no id_token in oauth2 token")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no id_token"})
			return
		}

		idToken, err := h.Verifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.Error().Err(err).Msg("failed to verify id_token")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify token"})
			return
		}

		// var claims struct {
		// 	Email         string `json:"email"`
		// 	EmailVerified bool   `json:"email_verified"`
		// 	Name          string `json:"name"`
		// 	PreferredUser string `json:"preferred_username"`
		// }

		var claimsMap map[string]interface{}

		if err := idToken.Claims(&claimsMap); err != nil {
			log.Error().Err(err).Msg("failed to parse claims")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse claims"})
			return
		}

		sessionData := &SessionData{
			Authenticated: true,
			Sub:           idToken.Subject,
			Name:          claimsMap["name"].(string),
			Username:      claimsMap["preferred_username"].(string),
			Email:         claimsMap["email"].(string),
			Claims:        claimsMap,
		}

		if h.gocloak != nil {
			realmRoles, clientRoles, groups, attributes, err := h.gocloak.FetchUserAuthorization(ctx, idToken.Subject)
			if err != nil {
				var authDenied *AuthorizationDeniedError
				if errors.As(err, &authDenied) {
					log.Warn().Err(err).Str("sub", idToken.Subject).Msg("authorization denied")
					c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "detail": authDenied.Error()})
					return
				}
				log.Error().Err(err).Msg("failed to fetch user authorization from Keycloak")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch authorization"})
				return
			}
			sessionData.RealmRoles = realmRoles
			sessionData.ClientRoles = clientRoles
			sessionData.Groups = groups
			sessionData.Attributes = attributes
		}

		err = h.SessionStore.SetSessionData(c.Request, c.Writer, sessionData)
		if err != nil {
			log.Error().Err(err).Msg("failed to save session")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save session"})
			return
		}

		// Call post-login hook if configured
		if h.Options.PostLoginHook != nil {
			if err := h.Options.PostLoginHook(c, sessionData); err != nil {
				log.Error().Err(err).Msg("post-login hook failed")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "post-login processing failed"})
				return
			}
		}

		// redirect to saved URL or home
		flash, err := h.SessionStore.GetStringFlash(c.Request, c.Writer)
		if err != nil {
			log.Error().Err(err).Msg("failed to get string flash")
		}
		if flash != nil {
			c.Redirect(http.StatusFound, *flash)
			return
		}
		c.Redirect(http.StatusFound, "/")
	}
}

func (h *Handler) logoutHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := h.SessionStore.Delete(c.Request, c.Writer)
		if err != nil {
			log.Error().Err(err).Msg("failed to delete session")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete session"})
			return
		}

		// Call post-logout hook if configured
		if h.Options.PostLogoutHook != nil {
			h.Options.PostLogoutHook(c)
		}

		log.Debug().Msg("user logged out")

		// Build logout URL with post_logout_redirect_uri if configured
		logoutTarget := h.Options.Provider.LogoutUri
		if h.Options.PostLogoutRedirectUri != "" && logoutTarget != "" {
			logoutURL, err := url.Parse(logoutTarget)
			if err == nil {
				q := logoutURL.Query()
				q.Set("client_id", h.Options.Provider.ClientId)
				q.Set("post_logout_redirect_uri", h.Options.PostLogoutRedirectUri)
				logoutURL.RawQuery = q.Encode()
				logoutTarget = logoutURL.String()
			}
		}
		if logoutTarget == "" {
			logoutTarget = "/"
		}
		c.Redirect(http.StatusFound, logoutTarget)
	}
}

func (h *Handler) userinfoHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionData, err := h.SessionStore.GetSessionData(c.Request)
		if err != nil || sessionData == nil || !sessionData.Authenticated {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusOK, sessionData)
	}
}
