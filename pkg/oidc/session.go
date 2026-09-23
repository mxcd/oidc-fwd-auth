package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const sessionIDKey = "sid"

// Backend keys of one session. Every piece of session state is its own key, so each
// operation touches only what it means to change.
const (
	dataKey        = "data"
	flashKey       = "flash"
	valueKeyPrefix = "value:"
)

func newSessionStore(options *SessionOptions) (*SessionStore, error) {
	if options.SameSite == http.SameSiteNoneMode && !options.Secure {
		return nil, fmt.Errorf("session cookie SameSite=None requires Secure=true, browsers reject it otherwise")
	}
	if options.Backend != nil && options.Redis != nil {
		return nil, fmt.Errorf("session Backend and Redis are mutually exclusive")
	}
	cookieStore := sessions.NewCookieStore([]byte(options.SecretSigningKey), []byte(options.SecretEncryptionKey))
	cookieStore.Options = &sessions.Options{
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: true,
		Path:     "/",
		SameSite: options.SameSite,
	}

	// Apply defaults
	if options.CacheSize == 0 {
		options.CacheSize = 10000
	}
	if options.CacheTTL == 0 {
		options.CacheTTL = time.Duration(options.MaxAge) * time.Second
	}

	backend := options.Backend
	switch {
	case backend != nil:
	case options.Redis != nil:
		applyRedisDefaults(options.Redis)
		backend = &redisBackend{
			client: redis.NewClient(&redis.Options{
				Addr:     fmt.Sprintf("%s:%d", options.Redis.Host, options.Redis.Port),
				Password: options.Redis.Password,
				DB:       options.Redis.DB,
			}),
			prefix: options.Redis.KeyPrefix,
		}
	default:
		backend = newLocalBackend(options.CacheSize, options.CacheTTL)
	}

	return &SessionStore{
		Options:       options,
		store:         cookieStore,
		backend:       backend,
		encryptionKey: []byte(options.SecretEncryptionKey),
	}, nil
}

func applyRedisDefaults(r *RedisSessionOptions) {
	if r.Port == 0 {
		r.Port = 6379
	}
	if r.KeyPrefix == "" {
		r.KeyPrefix = "oidc-sessions"
	}
}

// ttl is how long a value and a revocation marker live: the cookie's max age, or a day
// for a session cookie without one.
func (s *SessionStore) ttl() time.Duration {
	if s.Options.MaxAge > 0 {
		return time.Duration(s.Options.MaxAge) * time.Second
	}
	return 24 * time.Hour
}

func (s *SessionStore) put(ctx context.Context, sid, key string, plaintext []byte) error {
	ciphertext, err := encryptValue(s.encryptionKey, sid+"\x00"+key, plaintext)
	if err != nil {
		return err
	}
	return s.backend.Put(ctx, sid, key, ciphertext, s.ttl())
}

// read fetches one value with Get or Pop. A value that does not decrypt counts as absent.
func (s *SessionStore) read(ctx context.Context, sid, key string, pop bool) ([]byte, error) {
	var ciphertext []byte
	var ok bool
	var err error
	if pop {
		ciphertext, ok, err = s.backend.Pop(ctx, sid, key)
	} else {
		ciphertext, ok, err = s.backend.Get(ctx, sid, key)
	}
	if err != nil || !ok {
		return nil, err
	}
	plaintext, err := decryptValue(s.encryptionKey, sid+"\x00"+key, ciphertext)
	if err != nil {
		log.Error().Err(err).Str("key", key).Msg("failed to decrypt session value")
		return nil, nil
	}
	return plaintext, nil
}

// getSessionID reads the session ID from the cookie.
func (s *SessionStore) getSessionID(r *http.Request) (string, error) {
	session, err := s.store.Get(r, s.Options.Name)
	if err != nil {
		return "", err
	}
	sid, ok := session.Values[sessionIDKey].(string)
	if !ok || sid == "" {
		return "", nil
	}
	return sid, nil
}

// ensureSessionID creates a new session ID if one doesn't exist, saves the cookie, and returns the ID.
func (s *SessionStore) ensureSessionID(r *http.Request, w http.ResponseWriter) (string, error) {
	session, err := s.store.Get(r, s.Options.Name)
	if err != nil {
		return "", err
	}

	sid, ok := session.Values[sessionIDKey].(string)
	if ok && sid != "" {
		return sid, nil
	}

	sid = uuid.New().String()
	session.Values[sessionIDKey] = sid
	if err := session.Save(r, w); err != nil {
		return "", fmt.Errorf("failed to save session cookie: %w", err)
	}
	return sid, nil
}

// NewSession gives the request a fresh session ID; nothing is stored until a value is set.
func (s *SessionStore) NewSession(r *http.Request, w http.ResponseWriter) error {
	// Use Get (not New) so the session is registered in gorilla's per-request
	// registry. This ensures that subsequent store.Get calls within the same
	// HTTP request (e.g. from SetStringValue) return this session object with
	// the new session ID, rather than decoding the old cookie from the request.
	session, _ := s.store.Get(r, s.Options.Name)

	// Clear any values carried over from a previous session
	for k := range session.Values {
		delete(session.Values, k)
	}

	session.Values[sessionIDKey] = uuid.New().String()
	if err := session.Save(r, w); err != nil {
		return fmt.Errorf("failed to save session cookie: %w", err)
	}
	return nil
}

func (s *SessionStore) SetStringValue(r *http.Request, w http.ResponseWriter, key string, value string) error {
	sid, err := s.ensureSessionID(r, w)
	if err != nil {
		return err
	}
	return s.put(r.Context(), sid, valueKeyPrefix+key, []byte(value))
}

func (s *SessionStore) GetStringValue(r *http.Request, key string) (string, error) {
	return s.readStringValue(r, key, false)
}

// PopStringValue returns a value and deletes it in one atomic step, so it can be used
// once only (the login state).
func (s *SessionStore) PopStringValue(r *http.Request, key string) (string, error) {
	return s.readStringValue(r, key, true)
}

func (s *SessionStore) readStringValue(r *http.Request, key string, pop bool) (string, error) {
	sid, err := s.getSessionID(r)
	if err != nil || sid == "" {
		return "", err
	}
	value, err := s.read(r.Context(), sid, valueKeyPrefix+key, pop)
	return string(value), err
}

func (s *SessionStore) SetSessionData(r *http.Request, w http.ResponseWriter, data *SessionData) error {
	sid, err := s.ensureSessionID(r, w)
	if err != nil {
		return err
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}
	return s.put(r.Context(), sid, dataKey, plaintext)
}

func (s *SessionStore) GetSessionData(r *http.Request) (*SessionData, error) {
	sid, err := s.getSessionID(r)
	if err != nil {
		log.Error().Err(err).Msg("failed to get session ID")
		return nil, err
	}
	if sid == "" {
		log.Debug().Msg("no session ID found")
		return nil, nil
	}

	plaintext, err := s.read(r.Context(), sid, dataKey, false)
	if err != nil {
		return nil, err
	}
	if plaintext == nil {
		log.Debug().Msg("no session data found")
		return nil, nil
	}
	var data SessionData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		log.Error().Err(err).Msg("failed to unmarshal session data")
		return nil, nil
	}
	return &data, nil
}

// SetStringFlash stores a one-time value (the URL to return to after login). A session
// holds one flash; a later one replaces an earlier one.
func (s *SessionStore) SetStringFlash(r *http.Request, w http.ResponseWriter, value string) error {
	log.Debug().Msg("setting flash message in session")
	sid, err := s.ensureSessionID(r, w)
	if err != nil {
		return err
	}
	return s.put(r.Context(), sid, flashKey, []byte(value))
}

// GetStringFlash returns the flash and deletes it in one atomic step.
func (s *SessionStore) GetStringFlash(r *http.Request, w http.ResponseWriter) (*string, error) {
	log.Debug().Msg("getting flash message from session")
	sid, err := s.getSessionID(r)
	if err != nil || sid == "" {
		return nil, err
	}
	value, err := s.read(r.Context(), sid, flashKey, true)
	if err != nil || value == nil {
		return nil, err
	}
	flash := string(value)
	return &flash, nil
}

// Delete revokes the session in the backend (every key is deleted and no later write for
// this session ID is accepted) and expires the cookie.
func (s *SessionStore) Delete(r *http.Request, w http.ResponseWriter) error {
	sid, err := s.getSessionID(r)
	if err != nil {
		return err
	}

	if sid != "" {
		if err := s.backend.Revoke(r.Context(), sid, s.ttl()); err != nil {
			return err
		}
	}

	// Expire the cookie
	session, err := s.store.Get(r, s.Options.Name)
	if err != nil {
		return err
	}
	session.Options.MaxAge = -1
	return session.Save(r, w)
}
