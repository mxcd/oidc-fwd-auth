package oidc

import (
	"strings"
	"testing"
)

func TestValidateOptionsNil(t *testing.T) {
	err := validateOptions(nil)
	if err == nil {
		t.Fatal("expected error for nil options")
	}
}

func validTestOptions() *Options {
	return &Options{
		Provider: &ProviderOptions{
			Issuer:       "https://issuer.example.com",
			ClientId:     "client-id",
			ClientSecret: "client-secret",
			RedirectUri:  "https://app.example.com/callback",
		},
		Session: &SessionOptions{
			SecretSigningKey:    "signing-key-at-least-32-bytes!!!",
			SecretEncryptionKey: "01234567890123456789012345678901",
			Name:                "test-session",
			MaxAge:              3600,
		},
	}
}

func TestValidateOptionsValid(t *testing.T) {
	err := validateOptions(validTestOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOptionsMissingClientId(t *testing.T) {
	opts := validTestOptions()
	opts.Provider.ClientId = ""
	err := validateOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "client ID") {
		t.Errorf("expected client ID error, got: %v", err)
	}
}

func TestValidateOptionsMissingClientSecret(t *testing.T) {
	opts := validTestOptions()
	opts.Provider.ClientSecret = ""
	err := validateOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "client secret") {
		t.Errorf("expected client secret error, got: %v", err)
	}
}

func TestValidateOptionsMissingIssuer(t *testing.T) {
	opts := validTestOptions()
	opts.Provider.Issuer = ""
	err := validateOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Errorf("expected issuer error, got: %v", err)
	}
}

func TestValidateOptionsMissingRedirectUri(t *testing.T) {
	opts := validTestOptions()
	opts.Provider.RedirectUri = ""
	err := validateOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "redirect URI") {
		t.Errorf("expected redirect URI error, got: %v", err)
	}
}

func TestValidateOptionsMissingSigningKey(t *testing.T) {
	opts := validTestOptions()
	opts.Session.SecretSigningKey = ""
	err := validateOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Errorf("expected signing key error, got: %v", err)
	}
}

func TestValidateOptionsWrongEncryptionKeyLength(t *testing.T) {
	opts := validTestOptions()
	opts.Session.SecretEncryptionKey = "too-short"
	err := validateOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "32 or 64 bytes") {
		t.Errorf("expected encryption key length error, got: %v", err)
	}
}

func TestValidateOptions64ByteEncryptionKey(t *testing.T) {
	opts := validTestOptions()
	opts.Session.SecretEncryptionKey = "0123456789012345678901234567890101234567890123456789012345678901"
	err := validateOptions(opts)
	if err != nil {
		t.Fatalf("64-byte key should be valid: %v", err)
	}
}

func TestValidateOptionsMissingSessionName(t *testing.T) {
	opts := validTestOptions()
	opts.Session.Name = ""
	err := validateOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "session name") {
		t.Errorf("expected session name error, got: %v", err)
	}
}

func TestValidateOptionsRedisEmptyHost(t *testing.T) {
	opts := validTestOptions()
	opts.Session.Redis = &RedisSessionOptions{
		Host: "",
	}
	err := validateOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "redis host") {
		t.Errorf("expected redis host error, got: %v", err)
	}
}

func TestValidateOptionsRedisWithHost(t *testing.T) {
	opts := validTestOptions()
	opts.Session.Redis = &RedisSessionOptions{
		Host: "redis.example.com",
	}
	err := validateOptions(opts)
	if err != nil {
		t.Fatalf("redis with host should be valid: %v", err)
	}
}
