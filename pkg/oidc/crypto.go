package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
)

func encryptSessionEntry(key []byte, entry *sessionEntry) ([]byte, error) {
	plaintext, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session entry: %w", err)
	}

	// Use first 32 bytes of key for AES-256
	aesKey := key[:32]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Prepend nonce to ciphertext
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptSessionEntry(key []byte, ciphertext []byte) (*sessionEntry, error) {
	aesKey := key[:32]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session entry: %w", err)
	}

	var entry sessionEntry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session entry: %w", err)
	}

	return &entry, nil
}
