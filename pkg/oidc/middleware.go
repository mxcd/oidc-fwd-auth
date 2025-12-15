package oidc

import "github.com/gin-gonic/gin"

func (h *Handler) GetUiAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionData, err := h.SessionStore.GetSessionData(c.Request)
		if err != nil || sessionData == nil || !sessionData.Authenticated {
			// Save the current URL to redirect after login
			_ = h.SessionStore.SetStringFlash(c.Request, c.Writer, c.Request.URL.Path)
			c.Redirect(302, h.Options.AuthBaseUrl+"/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (h *Handler) GetApiAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionData, err := h.SessionStore.GetSessionData(c.Request)
		if err != nil || sessionData == nil || !sessionData.Authenticated {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}
