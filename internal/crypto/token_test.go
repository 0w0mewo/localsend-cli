package crypto

import (
	"testing"
	"time"
)

func TestGenerateKeyPair(t *testing.T) {
	key, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if key == nil {
		t.Fatal("GenerateKeyPair returned nil")
	}
	if len(key.publicKey) == 0 {
		t.Error("Public key is empty")
	}
	if len(key.privateKey) == 0 {
		t.Error("Private key is empty")
	}
}

func TestGenerateTokenTimestamp(t *testing.T) {
	key, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	token, err := key.GenerateTokenTimestamp()
	if err != nil {
		t.Fatalf("GenerateTokenTimestamp failed: %v", err)
	}

	// Token format: sha256.{hash}.{salt}.ed25519.{signature}
	if token == "" {
		t.Error("Token is empty")
	}

	// Verify the token
	verifyingKey := key.ToVerifyingKey()
	err = VerifyTokenTimestamp(verifyingKey, token)
	if err != nil {
		t.Errorf("VerifyTokenTimestamp failed: %v", err)
	}
}

func TestGenerateTokenWithNonce(t *testing.T) {
	key, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce failed: %v", err)
	}

	token, err := key.GenerateToken(nonce)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Verify with correct nonce
	verifyingKey := key.ToVerifyingKey()
	err = VerifyTokenNonce(verifyingKey, token, nonce)
	if err != nil {
		t.Errorf("VerifyTokenNonce failed: %v", err)
	}

	// Verify with wrong nonce should fail
	wrongNonce := make([]byte, 32)
	err = VerifyTokenNonce(verifyingKey, token, wrongNonce)
	if err == nil {
		t.Error("VerifyTokenNonce should fail with wrong nonce")
	}
}

func TestTokenExpiry(t *testing.T) {
	key, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Generate a token with a timestamp from 2 hours ago
	oldTimestamp := time.Now().Add(-2 * time.Hour).Unix()
	salt := make([]byte, 8)
	salt[0] = byte(oldTimestamp)
	salt[1] = byte(oldTimestamp >> 8)
	salt[2] = byte(oldTimestamp >> 16)
	salt[3] = byte(oldTimestamp >> 24)
	salt[4] = byte(oldTimestamp >> 32)
	salt[5] = byte(oldTimestamp >> 40)
	salt[6] = byte(oldTimestamp >> 48)
	salt[7] = byte(oldTimestamp >> 56)

	token, err := key.GenerateToken(salt)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Verify should fail because token is expired
	verifyingKey := key.ToVerifyingKey()
	err = VerifyTokenTimestamp(verifyingKey, token)
	if err == nil {
		t.Error("VerifyTokenTimestamp should fail for expired token")
	}
}

func TestExtractSignatureMethod(t *testing.T) {
	tests := []struct {
		token    string
		expected string
	}{
		{"sha256.abc.def.ed25519.sig", "ed25519"},
		{"sha256.abc.def.rsa-pss.sig", "rsa-pss"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		got := ExtractSignatureMethod(tt.token)
		if got != tt.expected {
			t.Errorf("ExtractSignatureMethod(%q) = %q; want %q", tt.token, got, tt.expected)
		}
	}
}
