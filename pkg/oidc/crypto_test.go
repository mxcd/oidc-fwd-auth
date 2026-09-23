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
	for _, key := range [][]byte{testKey32(), testKey64()} {
		ciphertext, err := encryptValue(key, "sid\x00data", []byte("secret payload"))
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		plaintext, err := decryptValue(key, "sid\x00data", ciphertext)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if string(plaintext) != "secret payload" {
			t.Errorf("roundtrip mismatch: got %q", plaintext)
		}
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	ciphertext, err := encryptValue(testKey32(), "ad", []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if _, err := decryptValue([]byte("different-key-01234567890123456!"), "ad", ciphertext); err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

// A value moved to another session or key must not decrypt there.
func TestDecryptWithOtherAdditionalData(t *testing.T) {
	ciphertext, err := encryptValue(testKey32(), "sid-a\x00data", []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if _, err := decryptValue(testKey32(), "sid-b\x00data", ciphertext); err == nil {
		t.Fatal("expected decryption to fail for another session")
	}
	if _, err := decryptValue(testKey32(), "sid-a\x00flash", ciphertext); err == nil {
		t.Fatal("expected decryption to fail for another key")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	ciphertext, err := encryptValue(testKey32(), "ad", []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	if _, err := decryptValue(testKey32(), "ad", ciphertext); err == nil {
		t.Fatal("expected decryption to fail with tampered ciphertext")
	}
}

func TestDecryptTooShort(t *testing.T) {
	_, err := decryptValue(testKey32(), "ad", []byte("short"))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected 'too short' error, got: %v", err)
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	ct1, err := encryptValue(testKey32(), "ad", []byte("same"))
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}
	ct2, err := encryptValue(testKey32(), "ad", []byte("same"))
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}
	if string(ct1) == string(ct2) {
		t.Error("two encryptions of the same data should produce different ciphertexts (different nonces)")
	}
}
