package util

import "github.com/mxcd/go-config/config"

func InitConfig() error {
	err := config.LoadConfig([]config.Value{
		config.String("DEPLOYMENT_IMAGE_TAG").NotEmpty().Default("development"),

		config.String("LOG_LEVEL").NotEmpty().Default("info"),

		config.Int("PORT").Default(8080),
		config.String("HEALTH_ENDPOINT").Default("/auth/health"),
		config.String("FWD_AUTH_API_ENDPOINT").Default("/auth/api"),
		config.String("FWD_AUTH_UI_ENDPOINT").Default("/auth/ui"),
		config.String("JWKS_ENDPOINT").Default("/auth/JWKS"),

		config.Bool("ENABLE_USERINFO_ENDPOINT").Default(false),

		config.Bool("DEV").Default(false),

		config.String("SESSION_SIGNING_KEY").NotEmpty().Sensitive(),
		config.String("SESSION_ENCRYPTION_KEY").NotEmpty().Sensitive(), // 32 or 64 bytes
		config.String("SESSION_NAME").NotEmpty().Default("oidc_fwd_auth_session"),
		config.String("SESSION_DOMAIN").Default("localhost"),
		config.Int("SESSION_MAX_AGE").Default(86400),
		config.Bool("SESSION_SECURE").Default(true),
		config.Int("SESSION_CACHE_SIZE").Default(10000),

		config.Bool("SESSION_REDIS_ENABLED").Default(false),
		config.String("SESSION_REDIS_HOST").Default("localhost"),
		config.Int("SESSION_REDIS_PORT").Default(6379),
		config.String("SESSION_REDIS_PASSWORD").Sensitive().Default(""),
		config.Int("SESSION_REDIS_DB").Default(0),
		config.String("SESSION_REDIS_KEY_PREFIX").Default("oidc-sessions"),
		config.Bool("SESSION_REDIS_PUBSUB").Default(true),
		config.String("SESSION_REDIS_PUBSUB_CHANNEL").Default("oidc-session-events"),
		config.Bool("SESSION_REDIS_REMOTE_ASYNC").Default(false),
		config.Bool("SESSION_REDIS_PRELOAD").Default(false),

		config.String("OIDC_ENDPOINTS_BASE_URL").Default("http://localhost:8080"),
		config.String("OIDC_ENDPOINTS_BASE_CONTEXT_PATH").Default("/auth/oidc"),
		config.String("OIDC_WELL_KNOWN_URL").NotEmpty().Default("http://localhost:8000/realms/dev"),
		config.String("OIDC_LOGOUT_URL").Default("http://localhost:8000/realms/dev/protocol/openid-connect/logout?redirect_uri=http://localhost:8080/"),
		config.String("OIDC_CLIENT_ID").NotEmpty().Default("test-app"),
		config.String("OIDC_CLIENT_SECRET").NotEmpty().Sensitive().Default("test-app-secret"),
		config.String("OIDC_REDIRECT_URI").NotEmpty().Default("http://localhost:8080/auth/oidc/callback"),
		config.StringArray("OIDC_SCOPES").Default([]string{"openid", "profile", "email"}),

		config.Bool("KEYCLOAK_ENABLED").Default(false),
		config.String("KEYCLOAK_SERVER_URL").Default(""),
		config.String("KEYCLOAK_REALM").Default(""),
		config.String("KEYCLOAK_AUTH_METHOD").Default("password"),
		config.String("KEYCLOAK_USERNAME").Sensitive().Default(""),
		config.String("KEYCLOAK_PASSWORD").Sensitive().Default(""),
		config.String("KEYCLOAK_CLIENT_ID").Default(""),
		config.String("KEYCLOAK_CLIENT_SECRET").Sensitive().Default(""),
		config.StringArray("KEYCLOAK_REQUIRED_REALM_ROLES").Default([]string{}),
		config.StringArray("KEYCLOAK_REQUIRED_CLIENT_ROLES").Default([]string{}),
		config.String("KEYCLOAK_CLIENT_ROLES_CLIENT_ID").Default(""),
		config.StringArray("KEYCLOAK_REQUIRED_GROUPS").Default([]string{}),

		config.String("JWT_ISSUER").NotEmpty().Default("oidc-fwd-auth"),
		// generated using ssh-keygen -t rsa -b 4096 -E SHA512 -m PEM -P ""
		config.String("JWT_PRIVATE_KEY").NotEmpty().Sensitive().Default(""),
	})
	return err
}
