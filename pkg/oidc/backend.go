package oidc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/redis/go-redis/v9"
)

// ErrSessionRevoked is returned by SessionBackend.Put for a session that was revoked.
var ErrSessionRevoked = errors.New("session revoked")

// SessionBackend holds the server-side half of a session: one opaque value per session ID
// and key. Every operation must be atomic per key, and Put must be serialized against
// Revoke of the same session ID, so that once Revoke has returned no Put for that session
// ID can succeed until the marker expires. Values arrive encrypted by the library; the
// backend stores them as they are. Share one backend between replicas to make logins,
// logouts and front-channel logouts work across them; the library keeps no cache in front
// of it.
type SessionBackend interface {
	// Put stores value under (sid, key) for ttl, replacing an existing value. It returns
	// ErrSessionRevoked when sid carries a revocation marker.
	Put(ctx context.Context, sid, key string, value []byte, ttl time.Duration) error
	// Get returns the value under (sid, key); ok is false when there is none or it expired.
	Get(ctx context.Context, sid, key string) (value []byte, ok bool, err error)
	// Pop returns and deletes the value under (sid, key) in one atomic step: of two
	// concurrent Pops of one value at most one sees it.
	Pop(ctx context.Context, sid, key string) (value []byte, ok bool, err error)
	// Revoke deletes every key of sid and writes a revocation marker that lives for ttl.
	Revoke(ctx context.Context, sid string, ttl time.Duration) error
}

type localValue struct {
	value     []byte
	expiresAt time.Time
}

// localBackend is the in-process default: correct for a single replica only.
// ponytail: one mutex for every session and a size-bounded revocation list (an evicted
// marker lets a racing Put through again); configure a shared Backend or Redis for more.
type localBackend struct {
	mu       sync.Mutex
	sessions *expirable.LRU[string, map[string]localValue]
	revoked  *expirable.LRU[string, time.Time]
}

func newLocalBackend(size int, ttl time.Duration) *localBackend {
	return &localBackend{
		sessions: expirable.NewLRU[string, map[string]localValue](size, nil, ttl),
		revoked:  expirable.NewLRU[string, time.Time](size, nil, ttl),
	}
}

func (b *localBackend) Put(_ context.Context, sid, key string, value []byte, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if until, ok := b.revoked.Get(sid); ok && time.Now().Before(until) {
		return ErrSessionRevoked
	}
	values, ok := b.sessions.Get(sid)
	if !ok {
		values = make(map[string]localValue)
	}
	values[key] = localValue{value: value, expiresAt: time.Now().Add(ttl)}
	b.sessions.Add(sid, values)
	return nil
}

func (b *localBackend) Get(_ context.Context, sid, key string) ([]byte, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lookup(sid, key)
}

func (b *localBackend) Pop(_ context.Context, sid, key string) ([]byte, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	value, ok, err := b.lookup(sid, key)
	if ok {
		values, _ := b.sessions.Peek(sid)
		delete(values, key)
	}
	return value, ok, err
}

// lookup expects b.mu to be held.
func (b *localBackend) lookup(sid, key string) ([]byte, bool, error) {
	values, ok := b.sessions.Get(sid)
	if !ok {
		return nil, false, nil
	}
	v, ok := values[key]
	if !ok || !time.Now().Before(v.expiresAt) {
		return nil, false, nil
	}
	return v.value, true, nil
}

func (b *localBackend) Revoke(_ context.Context, sid string, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sessions.Remove(sid)
	b.revoked.Add(sid, time.Now().Add(ttl))
	return nil
}

// redisBackend keeps one string per value and a set indexing the session's keys. All keys
// of a session share the hash tag {sid}, so the scripts stay on one Redis Cluster slot.
type redisBackend struct {
	client *redis.Client
	prefix string
}

// KEYS: marker, value, index. ARGV: value, ttl in ms.
var redisPutScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('SET', KEYS[2], ARGV[1], 'PX', ARGV[2])
redis.call('SADD', KEYS[3], KEYS[2])
if redis.call('PTTL', KEYS[3]) < tonumber(ARGV[2]) then redis.call('PEXPIRE', KEYS[3], ARGV[2]) end
return 1
`)

// KEYS: marker, index. ARGV: ttl in ms.
var redisRevokeScript = redis.NewScript(`
for _, k in ipairs(redis.call('SMEMBERS', KEYS[2])) do redis.call('DEL', k) end
redis.call('DEL', KEYS[2])
redis.call('SET', KEYS[1], '1', 'PX', ARGV[1])
return 1
`)

func (b *redisBackend) indexKey(sid string) string  { return fmt.Sprintf("%s:{%s}", b.prefix, sid) }
func (b *redisBackend) markerKey(sid string) string { return b.indexKey(sid) + "#revoked" }
func (b *redisBackend) valueKey(sid, key string) string {
	return b.indexKey(sid) + ":" + key
}

func (b *redisBackend) Put(ctx context.Context, sid, key string, value []byte, ttl time.Duration) error {
	stored, err := redisPutScript.Run(ctx, b.client,
		[]string{b.markerKey(sid), b.valueKey(sid, key), b.indexKey(sid)},
		value, ttl.Milliseconds()).Int()
	if err != nil {
		return fmt.Errorf("failed to store session value: %w", err)
	}
	if stored == 0 {
		return ErrSessionRevoked
	}
	return nil
}

func (b *redisBackend) Get(ctx context.Context, sid, key string) ([]byte, bool, error) {
	return redisBytes(b.client.Get(ctx, b.valueKey(sid, key)).Bytes())
}

func (b *redisBackend) Pop(ctx context.Context, sid, key string) ([]byte, bool, error) {
	return redisBytes(b.client.GetDel(ctx, b.valueKey(sid, key)).Bytes())
}

func (b *redisBackend) Revoke(ctx context.Context, sid string, ttl time.Duration) error {
	err := redisRevokeScript.Run(ctx, b.client, []string{b.markerKey(sid), b.indexKey(sid)}, ttl.Milliseconds()).Err()
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}
	return nil
}

func redisBytes(value []byte, err error) ([]byte, bool, error) {
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to read session value: %w", err)
	}
	return value, true, nil
}
