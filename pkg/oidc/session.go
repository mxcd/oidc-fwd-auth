package oidc

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	gocache "github.com/mxcd/go-cache"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const sessionIDKey = "sid"

func newSessionStore(options *SessionOptions) (*SessionStore, error) {
	cookieStore := sessions.NewCookieStore([]byte(options.SecretSigningKey), []byte(options.SecretEncryptionKey))
	cookieStore.Options = &sessions.Options{
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: true,
		Path:     "/",
	}

	// Apply defaults
	if options.CacheSize == 0 {
		options.CacheSize = 10000
	}
	if options.CacheTTL == 0 {
		options.CacheTTL = time.Duration(options.MaxAge) * time.Second
	}

	encryptionKey := []byte(options.SecretEncryptionKey)

	var cache sessionCache
	if options.Redis != nil {
		applyRedisDefaults(options.Redis)

		redisOpts := &redis.Options{
			Addr:     fmt.Sprintf("%s:%d", options.Redis.Host, options.Redis.Port),
			Password: options.Redis.Password,
			DB:       options.Redis.DB,
		}

		storageBackend, err := gocache.NewRedisStorageBackend[string, []byte](&gocache.RedisStorageBackendOptions[string]{
			RedisOptions:      redisOpts,
			CacheKey:          &gocache.StringCacheKey{},
			KeyPrefix:         options.Redis.KeyPrefix,
			TTL:               options.Redis.TTL,
			PubSub:            options.Redis.PubSub,
			PubSubChannelName: options.Redis.PubSubChannelName,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create redis storage backend: %w", err)
		}

		syncCache, err := gocache.NewSynchronizedCache[string, []byte](&gocache.SynchronizedCacheOptions[string, []byte]{
			LocalTTL:       options.Redis.LocalTTL,
			LocalSize:      options.CacheSize,
			CacheKey:       &gocache.StringCacheKey{},
			StorageBackend: storageBackend,
			RemoteAsync:    options.Redis.RemoteAsync,
			Preload:        options.Redis.Preload,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create synchronized cache: %w", err)
		}

		cache = &syncCacheAdapter{cache: syncCache, encryptionKey: encryptionKey}
	} else {
		localCache := gocache.NewLocalCache[string, []byte](&gocache.LocalCacheOptions[string]{
			Size:     options.CacheSize,
			TTL:      options.CacheTTL,
			CacheKey: &gocache.StringCacheKey{},
		})
		cache = &localCacheAdapter{cache: localCache, encryptionKey: encryptionKey}
	}

	return &SessionStore{
		Options: options,
		store:   cookieStore,
		cache:   cache,
	}, nil
}

func applyRedisDefaults(r *RedisSessionOptions) {
	if r.Port == 0 {
		r.Port = 6379
	}
	if r.KeyPrefix == "" {
		r.KeyPrefix = "oidc-sessions"
	}
	if r.TTL == 0 {
		r.TTL = 24 * time.Hour
	}
	if r.LocalTTL == 0 {
		r.LocalTTL = 5 * time.Minute
	}
	if r.PubSubChannelName == "" {
		r.PubSubChannelName = "oidc-session-events"
	}
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

// getOrCreateEntry loads the session entry from cache or creates a new empty one.
func (s *SessionStore) getOrCreateEntry(ctx context.Context, sid string) *sessionEntry {
	entry, ok := s.cache.Get(ctx, sid)
	if ok && entry != nil {
		return entry
	}
	return &sessionEntry{
		Values: make(map[string]string),
	}
}

func (s *SessionStore) NewSession(r *http.Request, w http.ResponseWriter) error {
	session, err := s.store.New(r, s.Options.Name)
	if err != nil {
		return err
	}

	sid := uuid.New().String()
	session.Values[sessionIDKey] = sid
	if err := session.Save(r, w); err != nil {
		return fmt.Errorf("failed to save session cookie: %w", err)
	}

	// Create empty cache entry
	entry := &sessionEntry{
		Values: make(map[string]string),
	}
	return s.cache.Set(r.Context(), sid, entry)
}

func (s *SessionStore) SetStringValue(r *http.Request, w http.ResponseWriter, key string, value string) error {
	sid, err := s.ensureSessionID(r, w)
	if err != nil {
		return err
	}

	ctx := r.Context()
	entry := s.getOrCreateEntry(ctx, sid)
	if entry.Values == nil {
		entry.Values = make(map[string]string)
	}
	entry.Values[key] = value
	return s.cache.Set(ctx, sid, entry)
}

func (s *SessionStore) GetStringValue(r *http.Request, key string) (string, error) {
	sid, err := s.getSessionID(r)
	if err != nil {
		return "", err
	}
	if sid == "" {
		return "", nil
	}

	entry, ok := s.cache.Get(r.Context(), sid)
	if !ok || entry == nil {
		return "", nil
	}
	return entry.Values[key], nil
}

func (s *SessionStore) SetSessionData(r *http.Request, w http.ResponseWriter, data *SessionData) error {
	sid, err := s.ensureSessionID(r, w)
	if err != nil {
		return err
	}

	ctx := r.Context()
	entry := s.getOrCreateEntry(ctx, sid)
	entry.Data = data
	return s.cache.Set(ctx, sid, entry)
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

	entry, ok := s.cache.Get(r.Context(), sid)
	if !ok || entry == nil || entry.Data == nil {
		log.Debug().Msg("no session data found")
		return nil, nil
	}
	return entry.Data, nil
}

func (s *SessionStore) SetStringFlash(r *http.Request, w http.ResponseWriter, value string) error {
	log.Debug().Msg("setting flash message in session")
	sid, err := s.ensureSessionID(r, w)
	if err != nil {
		return err
	}

	ctx := r.Context()
	entry := s.getOrCreateEntry(ctx, sid)
	entry.Flashes = append(entry.Flashes, value)
	return s.cache.Set(ctx, sid, entry)
}

func (s *SessionStore) GetStringFlash(r *http.Request, w http.ResponseWriter) (*string, error) {
	log.Debug().Msg("getting flash message from session")
	sid, err := s.getSessionID(r)
	if err != nil {
		return nil, err
	}
	if sid == "" {
		return nil, nil
	}

	ctx := r.Context()
	entry, ok := s.cache.Get(ctx, sid)
	if !ok || entry == nil || len(entry.Flashes) == 0 {
		return nil, nil
	}

	flash := entry.Flashes[0]
	entry.Flashes = entry.Flashes[1:]
	if err := s.cache.Set(ctx, sid, entry); err != nil {
		return nil, err
	}
	return &flash, nil
}

func (s *SessionStore) Delete(r *http.Request, w http.ResponseWriter) error {
	sid, err := s.getSessionID(r)
	if err != nil {
		return err
	}

	if sid != "" {
		_ = s.cache.Remove(r.Context(), sid)
	}

	// Expire the cookie
	session, err := s.store.Get(r, s.Options.Name)
	if err != nil {
		return err
	}
	session.Options.MaxAge = -1
	return session.Save(r, w)
}

// localCacheAdapter wraps a local cache with encryption
type localCacheAdapter struct {
	cache         *gocache.LocalCache[string, []byte]
	encryptionKey []byte
}

func (a *localCacheAdapter) Get(_ context.Context, key string) (*sessionEntry, bool) {
	ciphertext, ok := a.cache.Get(key)
	if !ok || ciphertext == nil {
		return nil, false
	}
	entry, err := decryptSessionEntry(a.encryptionKey, *ciphertext)
	if err != nil {
		log.Error().Err(err).Msg("failed to decrypt session entry")
		return nil, false
	}
	return entry, true
}

func (a *localCacheAdapter) Set(_ context.Context, key string, value *sessionEntry) error {
	ciphertext, err := encryptSessionEntry(a.encryptionKey, value)
	if err != nil {
		return err
	}
	a.cache.Set(key, ciphertext)
	return nil
}

func (a *localCacheAdapter) Remove(_ context.Context, key string) error {
	a.cache.Remove(key)
	return nil
}

// syncCacheAdapter wraps a synchronized cache with encryption
type syncCacheAdapter struct {
	cache         *gocache.SynchronizedCache[string, []byte]
	encryptionKey []byte
}

func (a *syncCacheAdapter) Get(ctx context.Context, key string) (*sessionEntry, bool) {
	ciphertext, ok := a.cache.Get(ctx, key)
	if !ok || ciphertext == nil {
		return nil, false
	}
	entry, err := decryptSessionEntry(a.encryptionKey, *ciphertext)
	if err != nil {
		log.Error().Err(err).Msg("failed to decrypt session entry")
		return nil, false
	}
	return entry, true
}

func (a *syncCacheAdapter) Set(ctx context.Context, key string, value *sessionEntry) error {
	ciphertext, err := encryptSessionEntry(a.encryptionKey, value)
	if err != nil {
		return err
	}
	return a.cache.Set(ctx, key, ciphertext)
}

func (a *syncCacheAdapter) Remove(ctx context.Context, key string) error {
	return a.cache.Remove(ctx, key)
}
