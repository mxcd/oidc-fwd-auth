package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// testBackend is one default backend plus a way to let time pass for it.
type testBackend struct {
	name    string
	backend SessionBackend
	advance func(time.Duration)
}

func testBackends(t *testing.T) []testBackend {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return []testBackend{
		{name: "local", backend: newLocalBackend(100, time.Hour), advance: time.Sleep},
		{name: "redis", backend: &redisBackend{client: client, prefix: "test"}, advance: mr.FastForward},
	}
}

func TestSessionBackendContract(t *testing.T) {
	ctx := context.Background()
	for _, tb := range testBackends(t) {
		t.Run(tb.name, func(t *testing.T) {
			b := tb.backend
			if err := b.Put(ctx, "s1", "k", []byte("v1"), time.Hour); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if err := b.Put(ctx, "s1", "k", []byte("v2"), time.Hour); err != nil {
				t.Fatalf("second Put: %v", err)
			}
			if err := b.Put(ctx, "s2", "k", []byte("other"), time.Hour); err != nil {
				t.Fatalf("Put s2: %v", err)
			}
			if v, ok, err := b.Get(ctx, "s1", "k"); err != nil || !ok || string(v) != "v2" {
				t.Fatalf("Get: %q %v %v, want v2", v, ok, err)
			}
			if _, ok, err := b.Get(ctx, "s1", "missing"); err != nil || ok {
				t.Fatalf("Get missing: %v %v", ok, err)
			}
			if v, ok, err := b.Pop(ctx, "s1", "k"); err != nil || !ok || string(v) != "v2" {
				t.Fatalf("Pop: %q %v %v, want v2", v, ok, err)
			}
			if _, ok, _ := b.Get(ctx, "s1", "k"); ok {
				t.Fatal("value still present after Pop")
			}

			if err := b.Put(ctx, "s1", "a", []byte("1"), time.Hour); err != nil {
				t.Fatalf("Put a: %v", err)
			}
			if err := b.Revoke(ctx, "s1", time.Hour); err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			if _, ok, _ := b.Get(ctx, "s1", "a"); ok {
				t.Fatal("value still present after Revoke")
			}
			if err := b.Put(ctx, "s1", "a", []byte("1"), time.Hour); !errors.Is(err, ErrSessionRevoked) {
				t.Fatalf("Put after Revoke: %v, want ErrSessionRevoked", err)
			}
			if v, ok, _ := b.Get(ctx, "s2", "k"); !ok || string(v) != "other" {
				t.Fatal("Revoke touched another session")
			}
		})
	}
}

func TestSessionBackendExpiry(t *testing.T) {
	ctx := context.Background()
	for _, tb := range testBackends(t) {
		t.Run(tb.name, func(t *testing.T) {
			b := tb.backend
			if err := b.Put(ctx, "s", "k", []byte("v"), 50*time.Millisecond); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if err := b.Revoke(ctx, "r", 50*time.Millisecond); err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			tb.advance(100 * time.Millisecond)
			if _, ok, _ := b.Get(ctx, "s", "k"); ok {
				t.Error("value outlived its ttl")
			}
			if err := b.Put(ctx, "r", "k", []byte("v"), time.Hour); err != nil {
				t.Errorf("revocation marker outlived its ttl: %v", err)
			}
		})
	}
}

func TestSessionBackendPopIsAtomic(t *testing.T) {
	ctx := context.Background()
	for _, tb := range testBackends(t) {
		t.Run(tb.name, func(t *testing.T) {
			for i := 0; i < 50; i++ {
				if err := tb.backend.Put(ctx, "s", "state", []byte("x"), time.Hour); err != nil {
					t.Fatalf("Put: %v", err)
				}
				var wg sync.WaitGroup
				var winners atomic.Int32
				for g := 0; g < 8; g++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if _, ok, _ := tb.backend.Pop(ctx, "s", "state"); ok {
							winners.Add(1)
						}
					}()
				}
				wg.Wait()
				if n := winners.Load(); n != 1 {
					t.Fatalf("round %d: %d Pops saw the value, want exactly 1", i, n)
				}
			}
		})
	}
}

// Replica A reads (pops) the flash and writes a new one while replica B logs the same
// session out. Whatever the interleaving, once both are done the session is revoked: no
// data, no flash, and no further write is accepted. Before per-key operations the flash
// read rewrote the whole session and could bring the deleted data back.
func TestLogoutRacingAFlashRead(t *testing.T) {
	for _, tb := range testBackends(t) {
		t.Run(tb.name, func(t *testing.T) {
			replicaA := newTestSessionStoreWithBackend(t, tb.backend)
			replicaB := newTestSessionStoreWithBackend(t, tb.backend)

			for i := 0; i < 100; i++ {
				w := httptest.NewRecorder()
				if err := replicaA.NewSession(httptest.NewRequest("GET", "/", nil), w); err != nil {
					t.Fatalf("NewSession: %v", err)
				}
				if err := replicaA.SetSessionData(newRequestWithCookies(w), httptest.NewRecorder(), &SessionData{Authenticated: true, Sub: "u"}); err != nil {
					t.Fatalf("SetSessionData: %v", err)
				}
				if err := replicaA.SetStringFlash(newRequestWithCookies(w), httptest.NewRecorder(), "/page"); err != nil {
					t.Fatalf("SetStringFlash: %v", err)
				}

				var wg sync.WaitGroup
				wg.Add(3)
				go func() {
					defer wg.Done()
					_, _ = replicaA.GetStringFlash(newRequestWithCookies(w), httptest.NewRecorder())
				}()
				go func() {
					defer wg.Done()
					// a write racing the logout either lands first and is revoked with the
					// rest, or is refused
					_ = replicaA.SetStringFlash(newRequestWithCookies(w), httptest.NewRecorder(), "/other")
				}()
				go func() {
					defer wg.Done()
					if err := replicaB.Delete(newRequestWithCookies(w), httptest.NewRecorder()); err != nil {
						t.Errorf("Delete: %v", err)
					}
				}()
				wg.Wait()

				for name, store := range map[string]*SessionStore{"A": replicaA, "B": replicaB} {
					if data, _ := store.GetSessionData(newRequestWithCookies(w)); data != nil {
						t.Fatalf("round %d: replica %s still sees session data after logout", i, name)
					}
					if flash, _ := store.GetStringFlash(newRequestWithCookies(w), httptest.NewRecorder()); flash != nil {
						t.Fatalf("round %d: replica %s still sees flash %q after logout", i, name, *flash)
					}
				}
				err := replicaA.SetSessionData(newRequestWithCookies(w), httptest.NewRecorder(), &SessionData{Authenticated: true})
				if !errors.Is(err, ErrSessionRevoked) {
					t.Fatalf("round %d: write after logout: %v, want ErrSessionRevoked", i, err)
				}
			}
		})
	}
}

func newTestSessionStoreWithBackend(t *testing.T, backend SessionBackend) *SessionStore {
	t.Helper()
	store, err := newSessionStore(&SessionOptions{
		SecretSigningKey:    testSessionSigningKey,
		SecretEncryptionKey: testSessionEncryptionKey,
		Name:                "test-session",
		MaxAge:              3600,
		Backend:             backend,
	})
	if err != nil {
		t.Fatalf("failed to create session store: %v", err)
	}
	return store
}

func TestBackendAndRedisAreExclusive(t *testing.T) {
	_, err := newSessionStore(&SessionOptions{
		SecretSigningKey:    testSessionSigningKey,
		SecretEncryptionKey: testSessionEncryptionKey,
		Name:                "test-session",
		Backend:             newLocalBackend(1, time.Hour),
		Redis:               &RedisSessionOptions{Host: "localhost"},
	})
	if err == nil {
		t.Fatal("expected an error for Backend together with Redis")
	}
}

// newReplicas starts two handlers against one provider, like two replicas behind a load
// balancer. With a shared backend they share sessions; without one each keeps its own.
func newReplicas(t *testing.T, backend SessionBackend, hookA, hookB func(*gin.Context)) (*gin.Engine, *gin.Engine, *httptest.Server) {
	t.Helper()
	provider := newMockOIDCProvider(t, testClientID)
	replica := func(hook func(*gin.Context)) *gin.Engine {
		_, engine := newTestE2EHandlerWithOptions(t, provider, func(o *Options) {
			o.Session.Backend = backend
			o.PostLogoutHook = hook
		})
		return engine
	}
	return replica(hookA), replica(hookB), provider
}

// loginAcross starts the login on one replica and lands the provider's callback on
// another. It returns the callback response and the cookies after it.
func loginAcross(t *testing.T, start, callback *gin.Engine) (*httptest.ResponseRecorder, []*http.Cookie) {
	t.Helper()
	resp := performRequest(start, "GET", "/auth/oidc/login", nil)
	if resp.Code != http.StatusFound {
		t.Fatalf("login: expected 302, got %d", resp.Code)
	}
	cookies := collectCookies(nil, resp)
	loc, err := url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("login: invalid Location: %v", err)
	}
	state := loc.Query().Get("state")
	resp = performRequest(callback, "GET", "/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=test-code", cookies)
	return resp, collectCookies(cookies, resp)
}

func TestLoginAcrossReplicas(t *testing.T) {
	for _, tb := range testBackends(t) {
		t.Run(tb.name, func(t *testing.T) {
			replicaA, replicaB, _ := newReplicas(t, tb.backend, nil, nil)

			resp, cookies := loginAcross(t, replicaA, replicaB)
			if resp.Code != http.StatusFound {
				t.Fatalf("callback on B: expected 302, got %d (body: %s)", resp.Code, resp.Body.String())
			}
			for name, engine := range map[string]*gin.Engine{"A": replicaA, "B": replicaB} {
				if resp := performRequest(engine, "GET", "/auth/oidc/userinfo", cookies); resp.Code != http.StatusOK {
					t.Errorf("userinfo on %s: expected 200, got %d", name, resp.Code)
				}
			}

			// the state is single use: replaying the callback on A fails
			if resp := performRequest(replicaA, "GET", "/auth/oidc/callback?state=x&code=test-code", cookies); resp.Code != http.StatusBadRequest {
				t.Errorf("replayed callback: expected 400, got %d", resp.Code)
			}
		})
	}
}

// Without a shared backend the callback on the other replica finds no state: the failure
// the backend exists to fix.
func TestLoginAcrossReplicasNeedsASharedBackend(t *testing.T) {
	replicaA, replicaB, _ := newReplicas(t, nil, nil, nil)
	resp, _ := loginAcross(t, replicaA, replicaB)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("callback on B without a shared backend: expected 400, got %d", resp.Code)
	}
}

func TestLogoutAcrossReplicasSendsIdTokenHint(t *testing.T) {
	for _, tb := range testBackends(t) {
		t.Run(tb.name, func(t *testing.T) {
			replicaA, replicaB, provider := newReplicas(t, tb.backend, nil, nil)
			_, cookies := loginAcross(t, replicaA, replicaA)

			resp := performRequest(replicaB, "GET", "/auth/oidc/logout", cookies)
			if resp.Code != http.StatusFound {
				t.Fatalf("logout on B: expected 302, got %d", resp.Code)
			}
			loc, err := url.Parse(resp.Header().Get("Location"))
			if err != nil {
				t.Fatalf("invalid Location: %v", err)
			}
			if !strings.HasPrefix(loc.String(), provider.URL+"/logout") {
				t.Fatalf("expected the provider logout, got %s", loc)
			}
			hint := loc.Query().Get("id_token_hint")
			if strings.Count(hint, ".") != 2 {
				t.Fatalf("expected the id_token issued via A as id_token_hint, got %q", hint)
			}
			assertSessionGone(t, replicaA, cookies)
		})
	}
}

func TestFrontChannelLogoutAcrossReplicas(t *testing.T) {
	for _, tb := range testBackends(t) {
		t.Run(tb.name, func(t *testing.T) {
			hookCalled := false
			replicaA, replicaB, _ := newReplicas(t, tb.backend, func(*gin.Context) { hookCalled = true }, nil)
			_, cookies := loginAcross(t, replicaB, replicaB)

			resp := performRequestWithHeaders(replicaA, "GET", "/auth/oidc/logout", cookies, map[string]string{"Sec-Fetch-Dest": "iframe"})
			assertFrontChannelLogoutResponse(t, resp)
			if !hookCalled {
				t.Error("expected the PostLogoutHook on A to run")
			}
			assertSessionGone(t, replicaB, cookies)
		})
	}
}
