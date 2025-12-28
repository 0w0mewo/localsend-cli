package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// NonceSize is the default size for generated nonces.
const NonceSize = 32

// GenerateNonce generates a cryptographically secure random nonce.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// ValidateNonce checks if a nonce has a valid length (16-128 bytes).
func ValidateNonce(nonce []byte) bool {
	return len(nonce) >= 16 && len(nonce) <= 128
}

// EncodeNonce encodes a nonce to URL-safe base64 (no padding).
// Uses URL-safe encoding to match official LocalSend protocol.
func EncodeNonce(nonce []byte) string {
	return base64.RawURLEncoding.EncodeToString(nonce)
}

// DecodeNonce decodes a URL-safe base64-encoded nonce.
// Uses URL-safe encoding to match official LocalSend protocol.
func DecodeNonce(encoded string) ([]byte, error) {
	nonce, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if !ValidateNonce(nonce) {
		return nil, errors.New("invalid nonce length")
	}
	return nonce, nil
}

