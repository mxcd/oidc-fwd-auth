package jwt

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/rs/zerolog/log"
)

type SignerOptions struct {
	Algorithm     string
	JwtIssuer     string
	JwtPrivateKey string
}

type Signer struct {
	Options       *SignerOptions
	jwkPublicKey  jwk.Key
	jwkPrivateKey jwk.Key
	Jwks          jwk.Set
}

func NewSigner(options *SignerOptions) (*Signer, error) {
	block, _ := pem.Decode([]byte(options.JwtPrivateKey))
	if block == nil {
		log.Panic().Msg("failed to decode private key")
		return nil, fmt.Errorf("failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Panic().Err(err).Msg("failed to parse private key")
	}

	jwkPublicKey, err := jwk.FromRaw(privateKey.Public())
	if err != nil {
		log.Panic().Err(err).Msg("failed to create JWK from RSA private key")
	}

	err = jwkPublicKey.Set(jwk.KeyIDKey, "1")
	if err != nil {
		log.Panic().Err(err).Msg("failed to set key ID")
	}

	err = jwkPublicKey.Set(jwk.AlgorithmKey, "RS512")
	if err != nil {
		log.Panic().Err(err).Msg("failed to set algorithm")
	}

	err = jwkPublicKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
	if err != nil {
		log.Panic().Err(err).Msg("failed to set usage key")
	}

	err = jwkPublicKey.Set("iss", options.JwtIssuer)
	if err != nil {
		log.Panic().Err(err).Msg("failed to set issuer")
	}

	jwks := jwk.NewSet()

	jwks.AddKey(jwkPublicKey)

	jwkPrivateKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		log.Panic().Err(err).Msg("failed to create JWK from RSA private key")
	}
	jwkPrivateKey.Set(jwk.KeyIDKey, "1")
	jwkPrivateKey.Set(jwk.AlgorithmKey, "RS512")
	jwkPrivateKey.Set(jwk.KeyTypeKey, "JWT")
	jwkPrivateKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
	jwkPrivateKey.Set("iss", options.JwtIssuer)
	jwkPrivateKey.Set("jku", fmt.Sprintf("%s/JWKS", options.JwtIssuer))

	return &Signer{
		Options:       options,
		jwkPrivateKey: jwkPrivateKey,
		jwkPublicKey:  jwkPublicKey,
		Jwks:          jwks,
	}, nil
}

func (s *Signer) NewToken() jwt.Token {
	return jwt.New()
}

func (s *Signer) SignToken(token jwt.Token) ([]byte, error) {
	token.Set(jwt.IssuerKey, s.Options.JwtIssuer)
	token.Set(jwt.JwtIDKey, uuid.New().String())
	token.Set(jwt.IssuedAtKey, time.Now().Unix())
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Minute*time.Duration(30)).Unix())
	token.Set(jwt.NotBeforeKey, time.Now().Add(-time.Minute).Unix())

	hdrs := jws.NewHeaders()
	hdrs.Set(jws.JWKSetURLKey, fmt.Sprintf("%s/JWKS", s.Options.JwtIssuer))

	signedToken, err := jwt.Sign(token, jwt.WithKey(s.jwkPrivateKey.Algorithm(), s.jwkPrivateKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		log.Error().Err(err).Msg("error signing token")
		return nil, err
	}

	return signedToken, nil
}
