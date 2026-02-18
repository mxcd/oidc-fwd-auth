package oidc

import (
	"strings"
	"testing"
)

func testKey32() []byte {
	return []byte("01234567890123456789012345678901") // 32 bytes
}

func testKey64() []byte {
	return []byte("0123456789012345678901234567890101234567890123456789012345678901") // 64 bytes
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := testKey32()
	entry := &sessionEntry{
		Data: &SessionData{
			Authenticated: true,
			Sub:           "user-123",
			Name:          "Test User",
			Username:      "testuser",
			Email:         "test@example.com",
			Claims: map[string]interface{}{
				"role": "admin",
			},
		},
		Values: map[string]string{
			"state": "abc123",
		},
		Flashes: []string{"redirect-url"},
	}

	ciphertext, err := encryptSessionEntry(key, entry)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := decryptSessionEntry(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if decrypted.Data.Sub != entry.Data.Sub {
		t.Errorf("Sub mismatch: got %q, want %q", decrypted.Data.Sub, entry.Data.Sub)
	}
	if decrypted.Data.Name != entry.Data.Name {
		t.Errorf("Name mismatch: got %q, want %q", decrypted.Data.Name, entry.Data.Name)
	}
	if decrypted.Data.Email != entry.Data.Email {
		t.Errorf("Email mismatch: got %q, want %q", decrypted.Data.Email, entry.Data.Email)
	}
	if !decrypted.Data.Authenticated {
		t.Error("Authenticated should be true")
	}
	if decrypted.Values["state"] != "abc123" {
		t.Errorf("Values[state] mismatch: got %q", decrypted.Values["state"])
	}
	if len(decrypted.Flashes) != 1 || decrypted.Flashes[0] != "redirect-url" {
		t.Errorf("Flashes mismatch: got %v", decrypted.Flashes)
	}
}

func TestEncryptDecryptWith64ByteKey(t *testing.T) {
	key := testKey64()
	entry := &sessionEntry{
		Data: &SessionData{
			Authenticated: true,
			Sub:           "user-456",
		},
	}

	ciphertext, err := encryptSessionEntry(key, entry)
	if err != nil {
		t.Fatalf("encrypt with 64-byte key failed: %v", err)
	}

	decrypted, err := decryptSessionEntry(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt with 64-byte key failed: %v", err)
	}

	if decrypted.Data.Sub != "user-456" {
		t.Errorf("Sub mismatch: got %q", decrypted.Data.Sub)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1 := testKey32()
	key2 := []byte("different-key-01234567890123456!") // 32 bytes

	entry := &sessionEntry{
		Data: &SessionData{Sub: "secret"},
	}

	ciphertext, err := encryptSessionEntry(key1, entry)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, err = decryptSessionEntry(key2, ciphertext)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key := testKey32()
	entry := &sessionEntry{
		Data: &SessionData{Sub: "user"},
	}

	ciphertext, err := encryptSessionEntry(key, entry)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Tamper with the ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xff

	_, err = decryptSessionEntry(key, ciphertext)
	if err == nil {
		t.Fatal("expected decryption to fail with tampered ciphertext")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := testKey32()
	_, err := decryptSessionEntry(key, []byte("short"))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected 'too short' error, got: %v", err)
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := testKey32()
	entry := &sessionEntry{
		Data: &SessionData{Sub: "user"},
	}

	ct1, err := encryptSessionEntry(key, entry)
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}

	ct2, err := encryptSessionEntry(key, entry)
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}

	if string(ct1) == string(ct2) {
		t.Error("two encryptions of the same data should produce different ciphertexts (different nonces)")
	}
}

func TestEncryptDecryptEmptyEntry(t *testing.T) {
	key := testKey32()
	entry := &sessionEntry{}

	ciphertext, err := encryptSessionEntry(key, entry)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := decryptSessionEntry(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if decrypted.Data != nil {
		t.Error("expected nil Data")
	}
	if decrypted.Values != nil {
		t.Error("expected nil Values")
	}
	if decrypted.Flashes != nil {
		t.Error("expected nil Flashes")
	}
}

func TestEncryptDecryptLargeClaimsMap(t *testing.T) {
	key := testKey32()
	claims := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		claims[strings.Repeat("k", i+1)] = strings.Repeat("v", 100)
	}

	entry := &sessionEntry{
		Data: &SessionData{
			Authenticated: true,
			Claims:        claims,
		},
	}

	ciphertext, err := encryptSessionEntry(key, entry)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := decryptSessionEntry(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if len(decrypted.Data.Claims) != 100 {
		t.Errorf("expected 100 claims, got %d", len(decrypted.Data.Claims))
	}
}
