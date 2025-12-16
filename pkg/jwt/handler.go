package jwt

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/rs/zerolog/log"
	"github.com/zeebo/blake3"
)

type HandlerOptions struct {
	JwksUrl             string
	JwksRefreshInterval time.Duration
	LocalJwks           *jwk.Set
	Cached              bool
	CacheSize           int
	TTL                 time.Duration
	HeaderKey           string
}

type Handler struct {
	Jwks    *jwk.Set
	Options *HandlerOptions
	lock    sync.Mutex
	cache   *expirable.LRU[string, jwt.Token]
}

type User struct {
	UserId   int      `json:"userId"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Teams    []string `json:"teams"`
}

func NewHandler(options *HandlerOptions) (*Handler, error) {

	if options.JwksRefreshInterval == 0 {
		options.JwksRefreshInterval = 300
	}

	if options.HeaderKey == "" {
		options.HeaderKey = "Authorization"
	}

	handler := &Handler{
		Options: options,
		lock:    sync.Mutex{},
	}

	if options.Cached {
		if options.CacheSize == 0 {
			options.CacheSize = 1000
		}
		if options.TTL == 0 {
			options.TTL = 300
		}
		handler.cache = expirable.NewLRU[string, jwt.Token](options.CacheSize, nil, options.TTL)
	}

	fetchJwks := func() (*jwk.Set, error) {
		ctx := context.Background()
		jwks, err := jwk.Fetch(ctx, options.JwksUrl)
		if err != nil {
			log.Error().Err(err).Msg("failed to fetch JWKS")
			return nil, err
		} else {
			log.Debug().Msg("successfully fetched JWKS")
		}

		if options.LocalJwks != nil {
			iter := (*options.LocalJwks).Keys(context.Background())
			for iter.Next(context.Background()) {
				key := iter.Pair().Value.(jwk.Key)
				err = jwks.AddKey(key)
				if err != nil {
					log.Error().Err(err).Msg("failed to add local key to JWKS")
					return nil, err
				}
			}
		}
		return &jwks, nil
	}

	jwks, err := fetchJwks()
	if err != nil {
		return nil, err
	}
	handler.Jwks = jwks

	go func() {
		ticker := time.NewTicker(options.JwksRefreshInterval)
		for range ticker.C {
			jwks, err := fetchJwks()
			if err == nil {
				handler.lock.Lock()
				handler.Jwks = jwks
				handler.lock.Unlock()
			}
		}
	}()

	return handler, nil
}

func (h *Handler) GetJwks() *jwk.Set {
	h.lock.Lock()
	defer h.lock.Unlock()
	return h.Jwks
}

func (h *Handler) GetTokenFromRequest(request *http.Request) (jwt.Token, error) {
	tokenHash, err := h.getTokenHashFromRequest(request)
	if err != nil {
		return nil, err
	}

	if h.Options.Cached {
		token, ok := h.cache.Get(tokenHash)
		if ok {
			return token, nil
		}
	}

	token, err := jwt.ParseRequest(request, jwt.WithVerify(true), jwt.WithValidate(true), jwt.WithKeySet(*h.GetJwks()))
	if err != nil {
		return nil, err
	}

	if h.Options.Cached {
		h.cache.Add(tokenHash, token)
	}

	return token, nil
}

func (h *Handler) getTokenHashFromRequest(request *http.Request) (string, error) {
	token := request.Header.Get(h.Options.HeaderKey)
	if token == "" {
		return "", errors.New("no token found in request")
	}

	hasher := blake3.New()
	hasher.WriteString(token)
	sum := hasher.Sum([]byte{})

	return string(sum), nil
}

func (h *Handler) GetUserFromToken(token jwt.Token) (*User, error) {
	userId, ok := token.Get("uid")
	if !ok {
		return nil, errors.New("no user id found in token")
	}

	username, ok := token.Get("sub")
	if !ok {
		return nil, errors.New("no username found in token")
	}

	name, ok := token.Get("name")
	if !ok {
		return nil, errors.New("no name found in token")
	}

	email, ok := token.Get("email")
	if !ok {
		return nil, errors.New("no email found in token")
	}

	teamsInterface, ok := token.Get("teams")
	if !ok {
		log.Warn().Msgf("no teams found in token for user %s", username)
	}

	teams := []string{}
	for _, team := range teamsInterface.([]interface{}) {
		teams = append(teams, team.(string))
	}

	return &User{
		UserId:   int(userId.(float64)),
		Username: username.(string),
		Name:     name.(string),
		Email:    email.(string),
		Teams:    teams,
	}, nil
}

func (h *Handler) GetUserFromRequest(request *http.Request) (*User, error) {
	token, err := h.GetTokenFromRequest(request)
	if err != nil {
		return nil, err
	}

	return h.GetUserFromToken(token)
}
