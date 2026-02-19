# OIDC Forward Authentication

A lightweight OIDC (OpenID Connect) forward authentication middleware for Traefik and other reverse proxies. This service handles authentication flows and can be used either as a standalone container or as a Go library integrated into your applications.

## Features

- Full OIDC authentication flow support
- JWT token generation with RS512 signing
- JWKS endpoint for token verification
- Secure session management with signed and encrypted cookies
- Traefik forward authentication integration
- Available as container or Go library
- Built with Gin framework for high performance
- Automatic OIDC provider discovery
- Optional Keycloak integration for role and group introspection via gocloak
- Optional Redis-backed distributed session store

## Usage Methods

### 1. Forward Authentication Container (Traefik)

Use as a forward authentication service with Traefik reverse proxy.

#### Docker Compose Example

```yaml
services:
  traefik:
    image: traefik:v3.4
    command:
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
    ports:
      - "80:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro

  fwd-auth:
    image: ghcr.io/mxcd/oidc-fwd-auth:latest
    environment:
      SESSION_DOMAIN: example.com
      SESSION_SIGNING_KEY: your-secret-signing-key
      SESSION_ENCRYPTION_KEY: the-32-or-64-byte-encryption-key
      OIDC_ENDPOINTS_BASE_URL: https://example.com
      OIDC_REDIRECT_URI: https://example.com/auth/oidc/callback
      OIDC_WELL_KNOWN_URL: https://your-oidc-provider.com/.well-known/openid-configuration
      OIDC_CLIENT_ID: your-client-id
      OIDC_CLIENT_SECRET: your-client-secret
      JWT_PRIVATE_KEY: |
        -----BEGIN RSA PRIVATE KEY-----
        your-private-key-here
        -----END RSA PRIVATE KEY-----
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.fwd-auth.rule=PathPrefix(`/auth`)"
      - "traefik.http.services.fwd-auth.loadbalancer.server.port=8080"

  your-app:
    image: your-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`example.com`)"
      - "traefik.http.routers.app.middlewares=auth"
      - "traefik.http.middlewares.auth.forwardauth.address=http://fwd-auth:8080/auth/ui"
      - "traefik.http.middlewares.auth.forwardauth.authResponseHeaders=Authorization"
```

#### Kubernetes Ingress Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oidc-fwd-auth
spec:
  replicas: 2
  selector:
    matchLabels:
      app: oidc-fwd-auth
  template:
    metadata:
      labels:
        app: oidc-fwd-auth
    spec:
      containers:
      - name: fwd-auth
        image: ghcr.io/mxcd/oidc-fwd-auth:latest
        ports:
        - containerPort: 8080
        env:
        - name: SESSION_DOMAIN
          value: "example.com"
        - name: SESSION_SIGNING_KEY
          valueFrom:
            secretKeyRef:
              name: oidc-secrets
              key: signing-key
        - name: SESSION_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: oidc-secrets
              key: encryption-key
        - name: OIDC_ENDPOINTS_BASE_URL
          value: "https://example.com"
        - name: OIDC_REDIRECT_URI
          value: "https://example.com/auth/oidc/callback"
        - name: OIDC_WELL_KNOWN_URL
          value: "https://your-oidc-provider.com/.well-known/openid-configuration"
        - name: OIDC_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: oidc-secrets
              key: client-id
        - name: OIDC_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: oidc-secrets
              key: client-secret
        - name: JWT_PRIVATE_KEY
          valueFrom:
            secretKeyRef:
              name: oidc-secrets
              key: jwt-private-key
---
apiVersion: v1
kind: Service
metadata:
  name: oidc-fwd-auth
spec:
  selector:
    app: oidc-fwd-auth
  ports:
  - port: 8080
    targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: default-auth@kubernetescrd
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: your-app
            port:
              number: 80
      - path: /auth
        pathType: Prefix
        backend:
          service:
            name: oidc-fwd-auth
            port:
              number: 8080
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: auth
spec:
  forwardAuth:
    address: http://oidc-fwd-auth.default.svc.cluster.local:8080/auth/ui
    authResponseHeaders:
      - Authorization
```

### 2. Library Usage

Import and use the OIDC handler directly in your Go applications.

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/mxcd/oidc-fwd-auth/pkg/oidc"
    "github.com/mxcd/oidc-fwd-auth/pkg/jwt"
)

func main() {
    // Initialize OIDC handler
    oidcHandler, err := oidc.NewHandler(&oidc.Options{
        Provider: &oidc.ProviderOptions{
            Issuer:       "https://your-oidc-provider.com",
            ClientId:     "your-client-id",
            ClientSecret: "your-client-secret",
            RedirectUri:  "https://your-app.com/auth/callback",
            LogoutUri:    "https://your-oidc-provider.com/logout",
            Scopes:       []string{"openid", "profile", "email"},
        },
        Session: &oidc.SessionOptions{
            SecretSigningKey:    "your-secret-signing-key",
            SecretEncryptionKey: "your-32-or-64-byte-encryption-key",
            Name:                "oidc_session",
            Domain:              "your-app.com",
            MaxAge:              86400,
            Secure:              true,
        },
        AuthBaseUrl:            "https://your-app.com",
        AuthBaseContextPath:    "/auth/oidc",
        EnableUserInfoEndpoint: true,
    })
    if err != nil {
        panic(err)
    }

    // Initialize JWT signer (optional, for token generation)
    jwtSigner, err := jwt.NewSigner(&jwt.SignerOptions{
        Algorithm:     "RS512",
        JwtIssuer:     "your-app",
        JwtPrivateKey: "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
    })
    if err != nil {
        panic(err)
    }

    // Set up Gin router
    router := gin.Default()
    
    // Register OIDC routes (login, callback, logout)
    oidcHandler.RegisterRoutes(router)
    
    // Protected UI routes (redirects to login if not authenticated)
    protected := router.Group("/app")
    protected.Use(oidcHandler.GetUiAuthMiddleware())
    {
        protected.GET("/dashboard", func(c *gin.Context) {
            // Get session data
            sessionData, _ := oidcHandler.SessionStore.GetSessionData(c.Request)
            c.JSON(200, gin.H{
                "message": "Welcome to dashboard",
                "user":    sessionData,
            })
        })
    }

    // Protected API routes (returns 401 if not authenticated)
    api := router.Group("/api")
    api.Use(oidcHandler.GetApiAuthMiddleware())
    {
        api.GET("/profile", func(c *gin.Context) {
            // Get session data
            sessionData, _ := oidcHandler.SessionStore.GetSessionData(c.Request)
            c.JSON(200, sessionData)
        })
    }

    router.Run(":8080")
}
```

### 3. Library Usage with Keycloak Role/Group Introspection

When using Keycloak as your OIDC provider, you can enable role and group introspection. After a successful OIDC login, the middleware queries the Keycloak admin API to fetch the user's realm roles, client roles, and group memberships. These are then available in session data, on `gin.Context`, and in generated JWT claims.

```go
oidcHandler, err := oidc.NewHandler(&oidc.Options{
    Provider: &oidc.ProviderOptions{
        Issuer:       "https://keycloak.example.com/realms/my-realm",
        ClientId:     "my-app",
        ClientSecret: "my-app-secret",
        RedirectUri:  "https://my-app.com/auth/oidc/callback",
        LogoutUri:    "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/logout",
    },
    Session: &oidc.SessionOptions{
        SecretSigningKey:    "your-secret-signing-key",
        SecretEncryptionKey: "your-32-or-64-byte-encryption-key",
        Name:                "oidc_session",
        Domain:              "my-app.com",
        MaxAge:              86400,
        Secure:              true,
    },
    AuthBaseUrl:            "https://my-app.com",
    AuthBaseContextPath:    "/auth/oidc",
    EnableUserInfoEndpoint: true,
    Gocloak: &oidc.GocloakOptions{
        ServerURL:           "https://keycloak.example.com",
        Realm:               "my-realm",
        AuthMethod:          "client_credentials",
        ClientID:            "my-admin-client",
        ClientSecret:        "my-admin-client-secret",
        ClientRolesClientID: "my-app",           // fetch client roles for this client
        RequiredRealmRoles:  []string{"user"},    // deny access if missing (optional)
        RequiredGroups:      []string{"/staff"},  // deny access if missing (optional)
    },
})
```

After login, the middleware sets these values on `gin.Context` in both UI and API auth middlewares:

- `c.Get("sessionData")` - full `*oidc.SessionData` including `RealmRoles`, `ClientRoles`, `Groups`
- `c.Get("realmRoles")` - `[]string` of realm role names
- `c.Get("clientRoles")` - `[]string` of client role names
- `c.Get("groups")` - `[]string` of group paths (e.g., `/admins`)

When using the forward auth container, the generated JWT includes `realm_roles`, `client_roles`, and `groups` claims.

If required roles or groups are configured and the user lacks any of them, the callback returns HTTP 403 Forbidden instead of establishing a session.

## Environment Variables

### General Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DEPLOYMENT_IMAGE_TAG` | No | `development` | Image tag for deployment tracking |
| `LOG_LEVEL` | No | `info` | Logging level (`trace`, `debug`, `info`, `warn`, `error`) |
| `PORT` | No | `8080` | HTTP server port |
| `DEV` | No | `false` | Enable development mode (enables CORS, verbose logging) |

### Endpoints Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HEALTH_ENDPOINT` | No | `/auth/health` | Health check endpoint path |
| `FWD_AUTH_API_ENDPOINT` | No | `/auth/api` | Forward auth API endpoint (returns JWT in response body) |
| `FWD_AUTH_UI_ENDPOINT` | No | `/auth/ui` | Forward auth UI endpoint (redirects to login page) |
| `JWKS_ENDPOINT` | No | `/auth/jwks` | JWKS endpoint for public key discovery |
| `ENABLE_USERINFO_ENDPOINT` | No | `false` | Enable userinfo endpoint at `/auth/oidc/userinfo` |

### Session Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SESSION_SIGNING_KEY` | **Yes** | - | Secret key for signing session cookies (sensitive) |
| `SESSION_ENCRYPTION_KEY` | **Yes** | - | Secret key for encrypting session cookies (must be 32 or 64 bytes, sensitive) |
| `SESSION_NAME` | No | `oidc_fwd_auth_session` | Name of the session cookie |
| `SESSION_DOMAIN` | No | `localhost` | Domain for session cookie |
| `SESSION_MAX_AGE` | No | `86400` | Session max age in seconds (default: 24 hours) |
| `SESSION_SECURE` | No | `true` | Enable secure flag on session cookie (HTTPS only) |
| `SESSION_CACHE_SIZE` | No | `10000` | Maximum number of sessions kept in local cache |

### Redis Session Configuration (Optional)

Enable Redis for distributed session storage across multiple instances.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SESSION_REDIS_ENABLED` | No | `false` | Enable Redis-backed session storage |
| `SESSION_REDIS_HOST` | No | `localhost` | Redis server host |
| `SESSION_REDIS_PORT` | No | `6379` | Redis server port |
| `SESSION_REDIS_PASSWORD` | No | - | Redis password (sensitive) |
| `SESSION_REDIS_DB` | No | `0` | Redis database number |
| `SESSION_REDIS_KEY_PREFIX` | No | `oidc-sessions` | Key prefix for session entries in Redis |
| `SESSION_REDIS_PUBSUB` | No | `true` | Enable pub/sub for cache invalidation across instances |
| `SESSION_REDIS_PUBSUB_CHANNEL` | No | `oidc-session-events` | Pub/sub channel name |
| `SESSION_REDIS_REMOTE_ASYNC` | No | `false` | Write to Redis asynchronously |
| `SESSION_REDIS_PRELOAD` | No | `false` | Preload sessions from Redis on startup |

### OIDC Provider Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OIDC_ENDPOINTS_BASE_URL` | No | `http://localhost:8080` | Base URL where this service is accessible |
| `OIDC_ENDPOINTS_BASE_CONTEXT_PATH` | No | `/auth/oidc` | Base context path for OIDC endpoints |
| `OIDC_WELL_KNOWN_URL` | **Yes** | `http://localhost:8000/realms/dev` | OIDC provider's well-known configuration URL |
| `OIDC_LOGOUT_URL` | No | `http://localhost:8000/realms/dev/protocol/openid-connect/logout?redirect_uri=http://localhost:8080/` | OIDC provider's logout URL |
| `OIDC_CLIENT_ID` | **Yes** | `test-app` | OIDC client ID |
| `OIDC_CLIENT_SECRET` | **Yes** | `test-app-secret` | OIDC client secret (sensitive) |
| `OIDC_REDIRECT_URI` | **Yes** | `http://localhost:8080/auth/oidc/callback` | OAuth2 callback URI |
| `OIDC_SCOPES` | No | `openid,profile,email` | Comma-separated list of OIDC scopes |

### JWT Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_ISSUER` | No | `oidc-fwd-auth` | JWT issuer claim |
| `JWT_PRIVATE_KEY` | **Yes** | - | RSA private key for signing JWTs (PEM format, sensitive) |

### Keycloak Integration (Optional)

Enable Keycloak-specific role and group introspection via gocloak. After OIDC login, the middleware queries the Keycloak admin API for the user's realm roles, client roles, and group memberships. These are included in session data and JWT claims (`realm_roles`, `client_roles`, `groups`).

Authentication to the Keycloak admin API supports two methods:
- `password` - authenticates with username/password (the realm specified in `KEYCLOAK_REALM` is used for token exchange)
- `client_credentials` - authenticates with a service account client (recommended for production)

For `client_credentials`, create a client in your Keycloak realm with **Service accounts roles** enabled and assign it the `realm-management` client roles: `view-users`, `query-users`, `view-clients`, `query-clients`, `query-groups`.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KEYCLOAK_ENABLED` | No | `false` | Enable Keycloak role/group introspection |
| `KEYCLOAK_SERVER_URL` | When enabled | - | Keycloak base URL (e.g., `https://keycloak.example.com`) |
| `KEYCLOAK_REALM` | When enabled | - | Keycloak realm name |
| `KEYCLOAK_AUTH_METHOD` | No | `password` | Auth method: `password` or `client_credentials` |
| `KEYCLOAK_USERNAME` | For `password` auth | - | Admin username (sensitive) |
| `KEYCLOAK_PASSWORD` | For `password` auth | - | Admin password (sensitive) |
| `KEYCLOAK_CLIENT_ID` | For `client_credentials` | - | Service account client ID |
| `KEYCLOAK_CLIENT_SECRET` | For `client_credentials` | - | Service account client secret (sensitive) |
| `KEYCLOAK_CLIENT_ROLES_CLIENT_ID` | No | - | Client ID to fetch client roles for |
| `KEYCLOAK_REQUIRED_REALM_ROLES` | No | - | Comma-separated realm roles the user must have (403 if missing) |
| `KEYCLOAK_REQUIRED_CLIENT_ROLES` | No | - | Comma-separated client roles the user must have (403 if missing) |
| `KEYCLOAK_REQUIRED_GROUPS` | No | - | Comma-separated group paths the user must belong to (403 if missing) |

## Generating Required Keys

### Session Keys

```bash
# Generate signing key (any random string)
SESSION_SIGNING_KEY=$(openssl rand -base64 32)

# Generate encryption key (must be exactly 32 bytes for AES-256)
SESSION_ENCRYPTION_KEY=$(openssl rand -base64 32 | head -c 32)
```

### JWT RSA Key Pair

```bash
# Generate private key
ssh-keygen -t rsa -b 4096 -m PEM -f jwt_private_key -N ""

# The private key is in jwt_private_key
# Set JWT_PRIVATE_KEY to the contents of this file
```

## Endpoints

- **Health Check**: `GET /auth/health` - Service health status
- **JWKS**: `GET /auth/jwks` - JSON Web Key Set for JWT verification
- **Forward Auth (API)**: `GET /auth/api` - Returns JWT in response body (for API clients)
- **Forward Auth (UI)**: `GET /auth/ui` - Redirects to login if not authenticated (for browsers)
- **OIDC Login**: `GET /auth/oidc/login` - Initiates OIDC login flow
- **OIDC Callback**: `GET /auth/oidc/callback` - OAuth2 callback endpoint
- **OIDC Logout**: `GET /auth/oidc/logout` - Logout and clear session
- **User Info**: `GET /auth/oidc/userinfo` - Get current user info (if `ENABLE_USERINFO_ENDPOINT=true`)

## Building from Source

```bash
# Build binary
go build -o oidc-fwd-auth ./cmd/middleware

# Build Docker image
docker build -f docker/middleware.Dockerfile -t oidc-fwd-auth:latest .
```

## Development

```bash
# Run with Docker Compose (includes Keycloak for testing)
cd hack/compose
docker-compose up

# Access:
# - Application: http://localhost:9000/whoami // http://localhost:9000/whoami-secured
# - Keycloak Admin: http://localhost:8000 (admin/admin)
# - Traefik Dashboard: http://localhost:9000/dashboard/
```

## License

See LICENSE file for details.