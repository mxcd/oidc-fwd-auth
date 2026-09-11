package oidc

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (h *Handler) RegisterRoutes(engine *gin.Engine) {
	engine.GET(h.Options.AuthBaseContextPath+"/login", h.loginHandler())
	engine.GET(h.Options.AuthBaseContextPath+"/callback", h.callbackHandler())
	engine.GET(h.Options.AuthBaseContextPath+"/logout", h.logoutHandler())
	engine.GET(h.Options.AuthBaseContextPath+"/frontchannel-logout", h.frontChannelLogoutHandler())
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

		name, username, email := h.mapClaims(claimsMap)
		sessionData := &SessionData{
			Authenticated: true,
			Provider:      h.Options.Provider.Name,
			Sub:           idToken.Subject,
			Name:          name,
			Username:      username,
			Email:         email,
			IDToken:       rawIDToken,
			Claims:        claimsMap,
		}

		// Opaque access tokens are legitimate (Google issues them), so a failure
		// to read claims here is a debug line, never a failed login.
		accessTokenClaims, err := h.parseAccessTokenClaims(ctx, oauth2Token.AccessToken)
		if err != nil {
			log.Debug().Err(err).Msg("access token carries no readable claims")
		} else {
			sessionData.AccessTokenClaims = accessTokenClaims
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
		} else {
			// No Admin API: the tokens are the only source of authorization.
			h.applyTokenAuthorization(sessionData, claimsMap)
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
		if h.isFrontChannelLogout(c.Request) {
			h.frontChannelLogout(c)
			return
		}

		// RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0): read the session
		// before destroying it so the id_token_hint can go along to the provider. With a
		// shared session store (MultiHandler) only this provider's own token is a valid hint.
		var idTokenHint string
		if data, err := h.SessionStore.GetSessionData(c.Request); err == nil && data != nil && h.ownsSession(data) {
			idTokenHint = data.IDToken
		}

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

		logoutTarget := h.Options.Provider.LogoutUri
		if logoutTarget != "" {
			logoutURL, err := url.Parse(logoutTarget)
			if err == nil {
				q := logoutURL.Query()
				q.Set("client_id", h.Options.Provider.ClientId)
				if idTokenHint != "" {
					q.Set("id_token_hint", idTokenHint)
				}
				if h.Options.PostLogoutRedirectUri != "" {
					q.Set("post_logout_redirect_uri", h.Options.PostLogoutRedirectUri)
				}
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

// frontChannelLogoutHandler is the dedicated front-channel logout URI for providers that
// let the client register one. The shared /logout route also detects front-channel calls,
// for providers such as GAS that only accept one logout URI per client.
func (h *Handler) frontChannelLogoutHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		h.frontChannelLogout(c)
	}
}

// isFrontChannelLogout tells a provider-initiated call of the shared logout URI apart
// from a user clicking logout. OpenID Connect Front-Channel Logout 1.0 loads the URI in
// an iframe and adds iss and sid when the provider supports session identification;
// providers that send neither still trigger Sec-Fetch-Dest: iframe in the browser.
// That header is a heuristic: an application that itself runs inside an iframe must
// set DisableIframeLogoutDetection and register /frontchannel-logout instead.
func (h *Handler) isFrontChannelLogout(r *http.Request) bool {
	q := r.URL.Query()
	if q.Has("iss") || q.Has("sid") {
		return true
	}
	return !h.Options.DisableIframeLogoutDetection && r.Header.Get("Sec-Fetch-Dest") == "iframe"
}

// ownsSession reports whether the session was established through this handler's
// provider. Sessions written by a binary older than v0.7.0 carry no provider name and
// are owned by nobody: no hint is sent for them and no front-channel call ends them.
func (h *Handler) ownsSession(data *SessionData) bool {
	return data.Provider != "" && data.Provider == h.Options.Provider.Name
}

// frontChannelLogout answers the provider's iframe: drop the local session and reply
// with a cacheless page. No redirect (it would run inside the provider's logout page)
// and no 204 (browsers treat that as a navigation failure). Anyone who can make the
// browser load this URL can end the session (logout CSRF); the spec accepts that.
func (h *Handler) frontChannelLogout(c *gin.Context) {
	c.Header("Cache-Control", "no-store, must-revalidate, proxy-revalidate")
	c.Header("Pragma", "no-cache")

	q := c.Request.URL.Query()
	iss, sid := q.Get("iss"), q.Get("sid")
	if q.Has("iss") != q.Has("sid") || (q.Has("iss") && (iss == "" || sid == "")) {
		log.Warn().Msg("front-channel logout must send iss and sid together (both non-empty) or neither")
		c.String(http.StatusBadRequest, "iss and sid must be sent together")
		return
	}
	if iss != "" && iss != h.Options.Provider.Issuer {
		log.Warn().Str("iss", iss).Msg("front-channel logout from unexpected issuer")
		c.String(http.StatusBadRequest, "unexpected issuer")
		return
	}

	data, err := h.SessionStore.GetSessionData(c.Request)
	if err != nil || data == nil {
		// Without a readable session (cookie blocked as third-party, or already gone) the
		// expiring Set-Cookie is all that can be done; the server-side session, if any,
		// stays until it expires.
		log.Debug().Msg("front-channel logout without a readable session, expiring the cookie only")
		_ = h.SessionStore.Delete(c.Request, c.Writer)
		h.writeFrontChannelLogoutPage(c)
		return
	}
	if !h.ownsSession(data) {
		log.Debug().Str("provider", data.Provider).Msg("front-channel logout for another provider's session, nothing to do")
		h.writeFrontChannelLogoutPage(c)
		return
	}
	if sid != "" {
		sessionSid, _ := data.Claims["sid"].(string)
		if sessionSid != sid {
			log.Warn().Msg("front-channel logout sid does not match the session")
			c.String(http.StatusBadRequest, "unexpected session")
			return
		}
	}

	if err := h.SessionStore.Delete(c.Request, c.Writer); err != nil {
		log.Error().Err(err).Msg("front-channel logout failed to delete the session")
		c.String(http.StatusInternalServerError, "failed to delete session")
		return
	}
	if h.Options.PostLogoutHook != nil {
		h.runFrontChannelHook(c)
	}
	log.Debug().Msg("front-channel logout completed")
	h.writeFrontChannelLogoutPage(c)
}

// runFrontChannelHook runs the PostLogoutHook against an isolated writer: the hook
// sees its own header map and its status and body go nowhere. Only the Set-Cookie
// headers it produced (cookie cleanup must reach the browser) are copied back. A hook
// written for the RP-initiated path may redirect, answer 204 or JSON; inside the
// provider's iframe only the 200 page is acceptable.
func (h *Handler) runFrontChannelHook(c *gin.Context) {
	original := c.Writer
	isolated := newFrontChannelHookWriter()
	c.Writer = isolated
	h.Options.PostLogoutHook(c)
	c.Writer = original
	for _, cookie := range isolated.header.Values("Set-Cookie") {
		original.Header().Add("Set-Cookie", cookie)
	}
	if isolated.written {
		log.Warn().Int("status", isolated.status).Msg("PostLogoutHook tried to answer the front-channel logout itself, response discarded")
	}
}

// frontChannelHookWriter is a gin.ResponseWriter that never reaches the connection.
type frontChannelHookWriter struct {
	header  http.Header
	status  int
	size    int
	written bool
}

func newFrontChannelHookWriter() *frontChannelHookWriter {
	return &frontChannelHookWriter{header: http.Header{}, status: http.StatusOK, size: -1}
}

func (w *frontChannelHookWriter) Header() http.Header { return w.header }
func (w *frontChannelHookWriter) WriteHeader(code int) {
	if !w.written && code > 0 {
		w.status = code
	}
}
func (w *frontChannelHookWriter) WriteHeaderNow() {
	if !w.written {
		w.written = true
		w.size = 0
	}
}
func (w *frontChannelHookWriter) Write(b []byte) (int, error) {
	w.WriteHeaderNow()
	w.size += len(b)
	return len(b), nil
}
func (w *frontChannelHookWriter) WriteString(s string) (int, error) { return w.Write([]byte(s)) }
func (w *frontChannelHookWriter) Status() int                       { return w.status }
func (w *frontChannelHookWriter) Size() int                         { return w.size }
func (w *frontChannelHookWriter) Written() bool                     { return w.written }
func (w *frontChannelHookWriter) Flush()                            { w.WriteHeaderNow() }
func (w *frontChannelHookWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("front-channel logout hook cannot hijack the connection")
}
func (w *frontChannelHookWriter) CloseNotify() <-chan bool { return make(chan bool) }
func (w *frontChannelHookWriter) Pusher() http.Pusher      { return nil }

func (h *Handler) writeFrontChannelLogoutPage(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<!doctype html><html><head><title>Logged out</title></head><body></body></html>"))
}

func (h *Handler) userinfoHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionData, err := h.SessionStore.GetSessionData(c.Request)
		if err != nil || sessionData == nil || !sessionData.Authenticated {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		// The raw ID token stays in the encrypted session; it is not user info.
		public := *sessionData
		public.IDToken = ""
		c.JSON(http.StatusOK, public)
	}
}
