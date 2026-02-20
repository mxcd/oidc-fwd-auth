//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	traefikBaseURL  = "http://localhost:9000"
	keycloakBaseURL = "http://localhost:8000"
	testUsername     = "testuser"
	testPassword     = "testuser"
)

// composeFiles returns the -f flags for docker compose: the main file + the e2e override.
func composeFiles() []string {
	_, thisFile, _, _ := runtime.Caller(0)
	testDir := filepath.Dir(thisFile)
	return []string{
		"-f", filepath.Join(testDir, "../../hack/compose/docker-compose.yml"),
		"-f", filepath.Join(testDir, "docker-compose.override.yml"),
	}
}

func TestMain(m *testing.M) {
	if err := runCompose("up", "-d", "--build"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start docker compose stack: %v\n", err)
		os.Exit(1)
	}

	if err := waitForServices(120 * time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "services not ready: %v\n", err)
		fmt.Fprintln(os.Stderr, "\n=== docker compose ps ===")
		runCompose("ps", "-a")
		fmt.Fprintln(os.Stderr, "\n=== keycloak logs ===")
		runCompose("logs", "keycloak")
		fmt.Fprintln(os.Stderr, "\n=== fwd-auth logs ===")
		runCompose("logs", "fwd-auth")
		runCompose("down")
		os.Exit(1)
	}

	code := m.Run()

	runCompose("down")
	os.Exit(code)
}

func runCompose(args ...string) error {
	fullArgs := append([]string{"compose"}, composeFiles()...)
	fullArgs = append(fullArgs, args...)
	cmd := exec.Command("docker", fullArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func waitForServices(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}

	// Wait for Keycloak (check realm endpoint since /health/ready is on the management port which isn't exposed)
	attempt := 0
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("keycloak not ready within %v (after %d attempts)", timeout, attempt)
		}
		attempt++
		resp, err := client.Get(keycloakBaseURL + "/realms/dev/.well-known/openid-configuration")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[waitForServices] keycloak attempt %d: error: %v\n", attempt, err)
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Fprintf(os.Stderr, "[waitForServices] keycloak attempt %d: status=%d body=%s\n", attempt, resp.StatusCode, string(body[:min(len(body), 200)]))
			if resp.StatusCode == 200 {
				break
			}
		}
		time.Sleep(2 * time.Second)
	}

	// Wait for fwd-auth through Traefik
	attempt = 0
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("fwd-auth not ready within %v (after %d attempts)", timeout, attempt)
		}
		attempt++
		resp, err := client.Get(traefikBaseURL + "/auth/health")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[waitForServices] fwd-auth attempt %d: error: %v\n", attempt, err)
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Fprintf(os.Stderr, "[waitForServices] fwd-auth attempt %d: status=%d body=%s\n", attempt, resp.StatusCode, string(body[:min(len(body), 200)]))
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
}

// newBrowserClient creates an HTTP client with a cookie jar that stops on redirects
// so each hop can be inspected individually.
func newBrowserClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// mustFollowRedirect follows a single HTTP redirect, resolving relative URLs.
func mustFollowRedirect(t *testing.T, client *http.Client, resp *http.Response) *http.Response {
	t.Helper()
	loc := resp.Header.Get("Location")
	if loc == "" {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("no Location header in %d response (body: %s)", resp.StatusCode, string(body[:min(len(body), 500)]))
	}
	resp.Body.Close()

	target, err := resp.Request.URL.Parse(loc)
	if err != nil {
		t.Fatalf("failed to resolve redirect URL %q: %v", loc, err)
	}

	newResp, err := client.Get(target.String())
	if err != nil {
		t.Fatalf("failed to follow redirect to %s: %v", target, err)
	}
	return newResp
}

// mustFollowAllRedirects follows a chain of 3xx redirects until a non-redirect response.
func mustFollowAllRedirects(t *testing.T, client *http.Client, resp *http.Response, maxHops int) *http.Response {
	t.Helper()
	for i := 0; resp.StatusCode >= 300 && resp.StatusCode < 400; i++ {
		if i >= maxHops {
			t.Fatalf("too many redirects (> %d)", maxHops)
		}
		resp = mustFollowRedirect(t, client, resp)
	}
	return resp
}

// extractFormAction finds a form tag by ID (or the first form) and returns its action URL.
func extractFormAction(t *testing.T, body []byte, formID string) string {
	t.Helper()

	// Find form tag with given ID
	formRe := regexp.MustCompile(`<form[^>]*id="` + regexp.QuoteMeta(formID) + `"[^>]*>`)
	formTag := formRe.Find(body)
	if formTag == nil {
		// Fallback: try any form with an action
		formRe = regexp.MustCompile(`<form[^>]*action="[^"]*"[^>]*>`)
		formTag = formRe.Find(body)
	}
	if formTag == nil {
		t.Fatalf("could not find form %q in page:\n%s", formID, string(body[:min(len(body), 2000)]))
	}

	actionRe := regexp.MustCompile(`action="([^"]+)"`)
	matches := actionRe.FindSubmatch(formTag)
	if matches == nil {
		t.Fatalf("could not find action attribute in form tag: %s", string(formTag))
	}

	return strings.ReplaceAll(string(matches[1]), "&amp;", "&")
}

// keycloakSubmitLogin parses the Keycloak HTML login page, submits credentials,
// and handles any required action pages (e.g., VERIFY_PROFILE in Keycloak 26.x).
func keycloakSubmitLogin(t *testing.T, client *http.Client, loginPageResp *http.Response) *http.Response {
	t.Helper()

	body, err := io.ReadAll(loginPageResp.Body)
	loginPageResp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read Keycloak login page: %v", err)
	}

	actionURL := extractFormAction(t, body, "kc-form-login")

	form := url.Values{
		"username": {testUsername},
		"password": {testPassword},
	}

	resp, err := client.PostForm(actionURL, form)
	if err != nil {
		t.Fatalf("failed to POST login form to %s: %v", actionURL, err)
	}

	// Handle Keycloak required action pages (e.g., VERIFY_PROFILE)
	for i := 0; i < 5; i++ {
		// Follow any intermediate redirects
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			resp.Body.Close()
			if loc == "" {
				break
			}
			// If the redirect goes to our callback, we're done with Keycloak
			if strings.Contains(loc, "/auth/oidc/callback") {
				break
			}
			target, _ := resp.Request.URL.Parse(loc)
			resp, err = client.Get(target.String())
			if err != nil {
				t.Fatalf("failed to follow Keycloak redirect to %s: %v", target, err)
			}
		}

		// If we get a 200, check if it's a Keycloak required action form
		if resp.StatusCode == 200 {
			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatalf("failed to read Keycloak page: %v", err)
			}

			// Check for update-profile form (VERIFY_PROFILE required action)
			if strings.Contains(string(body), "kc-update-profile-form") {
				actionURL = extractFormAction(t, body, "kc-update-profile-form")
				form := url.Values{
					"firstName": {"Test"},
					"lastName":  {"User"},
					"email":     {"testuser@example.com"},
				}
				resp, err = client.PostForm(actionURL, form)
				if err != nil {
					t.Fatalf("failed to POST profile form: %v", err)
				}
				continue
			}

			// Not a known required action page — stop
			// Re-wrap body for caller
			resp.Body = io.NopCloser(strings.NewReader(string(body)))
			break
		}
		break
	}

	return resp
}

// performLogin does the full OIDC login flow starting from /auth/oidc/login.
// After this, the client's cookie jar contains a valid session.
func performLogin(t *testing.T, client *http.Client) {
	t.Helper()

	// GET /auth/oidc/login → 302 to Keycloak authorization endpoint
	resp, err := client.Get(traefikBaseURL + "/auth/oidc/login")
	if err != nil {
		t.Fatalf("GET /auth/oidc/login failed: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 302 from /auth/oidc/login, got %d: %s", resp.StatusCode, string(body))
	}

	// Follow redirect(s) to Keycloak login page (200 HTML)
	resp = mustFollowAllRedirects(t, client, resp, 10)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected Keycloak login page (200), got %d: %s", resp.StatusCode, string(body))
	}

	// Submit credentials to Keycloak
	resp = keycloakSubmitLogin(t, client, resp)

	// Follow redirects: Keycloak → callback → flash URL or /
	resp = mustFollowAllRedirects(t, client, resp, 10)
	resp.Body.Close()
}

// TestRealE2EFullLoginFlow tests the complete browser login flow:
// /whoami-secured → redirect to login → Keycloak → callback → session established → /whoami-secured returns 200
func TestRealE2EFullLoginFlow(t *testing.T) {
	client := newBrowserClient()

	// Step 1: Access the secured endpoint without a session
	resp, err := client.Get(traefikBaseURL + "/whoami-secured")
	if err != nil {
		t.Fatalf("GET /whoami-secured failed: %v", err)
	}

	// Should redirect through fwd-auth UI handler → login → Keycloak
	resp = mustFollowAllRedirects(t, client, resp, 10)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected Keycloak login page (200), got %d: %s", resp.StatusCode, string(body))
	}

	// Step 2: Submit Keycloak credentials
	resp = keycloakSubmitLogin(t, client, resp)

	// Follow redirects through callback and back
	resp = mustFollowAllRedirects(t, client, resp, 10)
	resp.Body.Close()

	// Step 3: Access the secured endpoint again — should succeed now
	resp, err = client.Get(traefikBaseURL + "/whoami-secured")
	if err != nil {
		t.Fatalf("GET /whoami-secured (authenticated) failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from /whoami-secured after login, got %d: %s", resp.StatusCode, string(body))
	}

	// The whoami service echoes all request headers — verify the JWT was injected
	if !strings.Contains(string(body), "Authorization: Bearer") {
		t.Errorf("expected Authorization header in whoami response:\n%s", string(body))
	}
}

// TestRealE2EUnauthenticatedAPI verifies that the API auth endpoint returns 401 without a session.
func TestRealE2EUnauthenticatedAPI(t *testing.T) {
	client := newBrowserClient()

	resp, err := client.Get(traefikBaseURL + "/auth/api")
	if err != nil {
		t.Fatalf("GET /auth/api failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 from /auth/api, got %d: %s", resp.StatusCode, string(body))
	}
}

// TestRealE2EUserinfo verifies the userinfo endpoint returns session data after login.
func TestRealE2EUserinfo(t *testing.T) {
	client := newBrowserClient()
	performLogin(t, client)

	resp, err := client.Get(traefikBaseURL + "/auth/oidc/userinfo")
	if err != nil {
		t.Fatalf("GET /auth/oidc/userinfo failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from /auth/oidc/userinfo, got %d: %s", resp.StatusCode, string(body))
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "testuser") {
		t.Errorf("expected 'testuser' in userinfo response:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "testuser@example.com") {
		t.Errorf("expected 'testuser@example.com' in userinfo response:\n%s", bodyStr)
	}
}

// TestRealE2ELogout verifies that logout destroys the session.
func TestRealE2ELogout(t *testing.T) {
	client := newBrowserClient()
	performLogin(t, client)

	// Logout should redirect to Keycloak's end_session_endpoint
	resp, err := client.Get(traefikBaseURL + "/auth/oidc/logout")
	if err != nil {
		t.Fatalf("GET /auth/oidc/logout failed: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 302 from /auth/oidc/logout, got %d: %s", resp.StatusCode, string(body))
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()

	// Verify the redirect goes to Keycloak
	if !strings.Contains(loc, "realms/dev") && !strings.Contains(loc, "logout") {
		t.Errorf("expected logout redirect to Keycloak, got %q", loc)
	}

	// After logout, the secured endpoint should redirect to login (no valid session)
	resp, err = client.Get(traefikBaseURL + "/whoami-secured")
	if err != nil {
		t.Fatalf("GET /whoami-secured after logout failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode == 200 {
		t.Fatal("expected redirect from /whoami-secured after logout, but got 200")
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /whoami-secured after logout, got %d", resp.StatusCode)
	}
}

// TestRealE2EOpenEndpoint verifies that the unprotected /whoami endpoint is accessible without auth.
func TestRealE2EOpenEndpoint(t *testing.T) {
	client := newBrowserClient()

	resp, err := client.Get(traefikBaseURL + "/whoami")
	if err != nil {
		t.Fatalf("GET /whoami failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 from /whoami, got %d: %s", resp.StatusCode, string(body))
	}
}

// extractJWTClaims parses the JWT from the Authorization header echoed by the whoami service.
func extractJWTClaims(t *testing.T, whoamiBody string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(whoamiBody, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Authorization: Bearer ") {
			token := strings.TrimPrefix(line, "Authorization: Bearer ")
			token = strings.TrimSpace(token)
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Fatalf("invalid JWT format: expected 3 parts, got %d", len(parts))
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("failed to decode JWT payload: %v", err)
			}
			var claims map[string]any
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatalf("failed to parse JWT claims: %v", err)
			}
			return claims
		}
	}
	t.Fatal("no Authorization header found in whoami response")
	return nil
}

// containsString checks if a []any slice contains a given string.
func containsString(slice []any, target string) bool {
	for _, v := range slice {
		if s, ok := v.(string); ok && s == target {
			return true
		}
	}
	return false
}

// TestRealE2EJWTContainsRealmRoles verifies that after login, the JWT injected by fwd-auth
// contains realm_roles from Keycloak gocloak introspection.
func TestRealE2EJWTContainsRealmRoles(t *testing.T) {
	client := newBrowserClient()
	performLogin(t, client)

	resp, err := client.Get(traefikBaseURL + "/whoami-secured")
	if err != nil {
		t.Fatalf("GET /whoami-secured failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	claims := extractJWTClaims(t, string(body))

	realmRoles, ok := claims["realm_roles"]
	if !ok {
		t.Fatal("JWT missing realm_roles claim")
	}
	realmRolesSlice, ok := realmRoles.([]any)
	if !ok {
		t.Fatalf("realm_roles is not an array: %T", realmRoles)
	}
	if !containsString(realmRolesSlice, "test-realm-role") {
		t.Errorf("expected 'test-realm-role' in realm_roles: %v", realmRolesSlice)
	}
}

// TestRealE2EJWTContainsClientRoles verifies that the JWT contains client_roles from Keycloak.
func TestRealE2EJWTContainsClientRoles(t *testing.T) {
	client := newBrowserClient()
	performLogin(t, client)

	resp, err := client.Get(traefikBaseURL + "/whoami-secured")
	if err != nil {
		t.Fatalf("GET /whoami-secured failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	claims := extractJWTClaims(t, string(body))

	clientRoles, ok := claims["client_roles"]
	if !ok {
		t.Fatal("JWT missing client_roles claim")
	}
	clientRolesSlice, ok := clientRoles.([]any)
	if !ok {
		t.Fatalf("client_roles is not an array: %T", clientRoles)
	}
	if !containsString(clientRolesSlice, "test-client-role") {
		t.Errorf("expected 'test-client-role' in client_roles: %v", clientRolesSlice)
	}
}

// TestRealE2EJWTContainsGroups verifies that the JWT contains groups from Keycloak.
func TestRealE2EJWTContainsGroups(t *testing.T) {
	client := newBrowserClient()
	performLogin(t, client)

	resp, err := client.Get(traefikBaseURL + "/whoami-secured")
	if err != nil {
		t.Fatalf("GET /whoami-secured failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	claims := extractJWTClaims(t, string(body))

	groups, ok := claims["groups"]
	if !ok {
		t.Fatal("JWT missing groups claim")
	}
	groupsSlice, ok := groups.([]any)
	if !ok {
		t.Fatalf("groups is not an array: %T", groups)
	}
	if !containsString(groupsSlice, "/test-group") {
		t.Errorf("expected '/test-group' in groups: %v", groupsSlice)
	}
}

// TestRealE2EUserinfoContainsRolesAndGroups verifies that the userinfo endpoint
// returns session data including roles and groups from Keycloak.
func TestRealE2EUserinfoContainsRolesAndGroups(t *testing.T) {
	client := newBrowserClient()
	performLogin(t, client)

	resp, err := client.Get(traefikBaseURL + "/auth/oidc/userinfo")
	if err != nil {
		t.Fatalf("GET /auth/oidc/userinfo failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Check RealmRoles
	realmRoles, ok := data["RealmRoles"]
	if !ok || realmRoles == nil {
		t.Fatal("expected RealmRoles in userinfo response")
	}
	realmRolesSlice, ok := realmRoles.([]any)
	if !ok {
		t.Fatalf("RealmRoles is not an array: %T", realmRoles)
	}
	if !containsString(realmRolesSlice, "test-realm-role") {
		t.Errorf("expected 'test-realm-role' in RealmRoles: %v", realmRolesSlice)
	}

	// Check ClientRoles
	clientRoles, ok := data["ClientRoles"]
	if !ok || clientRoles == nil {
		t.Fatal("expected ClientRoles in userinfo response")
	}
	clientRolesSlice, ok := clientRoles.([]any)
	if !ok {
		t.Fatalf("ClientRoles is not an array: %T", clientRoles)
	}
	if !containsString(clientRolesSlice, "test-client-role") {
		t.Errorf("expected 'test-client-role' in ClientRoles: %v", clientRolesSlice)
	}

	// Check Groups
	groups, ok := data["Groups"]
	if !ok || groups == nil {
		t.Fatal("expected Groups in userinfo response")
	}
	groupsSlice, ok := groups.([]any)
	if !ok {
		t.Fatalf("Groups is not an array: %T", groups)
	}
	if !containsString(groupsSlice, "/test-group") {
		t.Errorf("expected '/test-group' in Groups: %v", groupsSlice)
	}
}
