package oidc

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (h *Handler) RegisterRoutes(engine *gin.Engine) {
	engine.GET(h.Options.AuthBaseUrl+"/login", h.loginHandler())
	engine.GET(h.Options.AuthBaseUrl+"/callback", h.callbackHandler())
	engine.GET(h.Options.AuthBaseUrl+"/logout", h.logoutHandler())
	if h.Options.EnableUserInfoEndpoint {
		engine.GET(h.Options.AuthBaseUrl+"/userinfo", h.GetUiAuthMiddleware(), h.userinfoHandler())
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

		_, err = h.SessionStore.NewSession(c.Request, c.Writer)
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
			IdToken:       idToken,
		}

		err = h.SessionStore.SetSessionData(c.Request, c.Writer, sessionData)
		if err != nil {
			log.Error().Err(err).Msg("failed to save session")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save session"})
			return
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
		log.Debug().Msg("user logged out")
		c.Redirect(http.StatusFound, h.Options.Provider.LogoutUri)
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
