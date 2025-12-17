package jwt

import (
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Token represents a JWT with important fields and generic claims
type Token struct {
	// Standard JWT claims
	Issuer         string    `json:"iss,omitempty"`
	Subject        string    `json:"sub,omitempty"`
	Audience       []string  `json:"aud,omitempty"`
	ExpiresAt      time.Time `json:"exp,omitempty"`
	NotBefore      time.Time `json:"nbf,omitempty"`
	IssuedAt       time.Time `json:"iat,omitempty"`
	JWTID          string    `json:"jti,omitempty"`

	// Generic claims field for OIDC session claims
	Claims         map[string]interface{} `json:"claims,omitempty"`
}

// NewToken creates a new JWT token
func NewToken() *Token {
	return &Token{
		Claims: make(map[string]interface{}),
	}
}

// ToJWT converts the Token to a jwx JWT token
func (t *Token) ToJWT() jwt.Token {
	token := jwt.New()

	if t.Issuer != "" {
		token.Set(jwt.IssuerKey, t.Issuer)
	}
	if t.Subject != "" {
		token.Set(jwt.SubjectKey, t.Subject)
	}
	if len(t.Audience) > 0 {
		token.Set(jwt.AudienceKey, t.Audience)
	}
	if !t.ExpiresAt.IsZero() {
		token.Set(jwt.ExpirationKey, t.ExpiresAt.Unix())
	}
	if !t.NotBefore.IsZero() {
		token.Set(jwt.NotBeforeKey, t.NotBefore.Unix())
	}
	if !t.IssuedAt.IsZero() {
		token.Set(jwt.IssuedAtKey, t.IssuedAt.Unix())
	}
	if t.JWTID != "" {
		token.Set(jwt.JwtIDKey, t.JWTID)
	}

	// Add all claims
	for k, v := range t.Claims {
		token.Set(k, v)
	}

	return token
}

// FromJWT populates the Token from a jwx JWT token
func (t *Token) FromJWT(jwtToken jwt.Token) {
	if iss, ok := jwtToken.Issuer(); ok {
		t.Issuer = iss
	}
	if sub, ok := jwtToken.Subject(); ok {
		t.Subject = sub
	}
	if aud, ok := jwtToken.Audience(); ok {
		t.Audience = aud
	}
	if exp, ok := jwtToken.Expiration(); ok {
		t.ExpiresAt = exp
	}
	if nbf, ok := jwtToken.NotBefore(); ok {
		t.NotBefore = nbf
	}
	if iat, ok := jwtToken.IssuedAt(); ok {
		t.IssuedAt = iat
	}
	if jti, ok := jwtToken.JwtID(); ok {
		t.JWTID = jti
	}

	// Extract all claims
	t.Claims = make(map[string]interface{})
	for _, key := range jwtToken.Keys() {
		if key == "iss" || key == "sub" || key == "aud" || key == "exp" || key == "nbf" || key == "iat" || key == "jti" {
			continue
		}
		var value interface{}
		if err := jwtToken.Get(key, &value); err == nil {
			t.Claims[key] = value
		}
	}
}