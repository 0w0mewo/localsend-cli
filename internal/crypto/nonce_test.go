package crypto

import (
	"strings"
	"testing"
)

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce failed: %v", err)
	}
	if len(nonce) != NonceSize {
		t.Errorf("Nonce size = %d; want %d", len(nonce), NonceSize)
	}
}

func TestValidateNonce(t *testing.T) {
	tests := []struct {
		size  int
		valid bool
	}{
		{15, false},  // Too small
		{16, true},   // Minimum valid
		{32, true},   // Default size
		{128, true},  // Maximum valid
		{129, false}, // Too large
	}

	for _, tt := range tests {
		nonce := make([]byte, tt.size)
		got := ValidateNonce(nonce)
		if got != tt.valid {
			t.Errorf("ValidateNonce(size=%d) = %v; want %v", tt.size, got, tt.valid)
		}
	}
}

func TestNonceEncodeDecode(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce failed: %v", err)
	}

	encoded := EncodeNonce(nonce)
	if encoded == "" {
		t.Error("Encoded nonce is empty")
	}

	decoded, err := DecodeNonce(encoded)
	if err != nil {
		t.Fatalf("DecodeNonce failed: %v", err)
	}

	if len(decoded) != len(nonce) {
		t.Errorf("Decoded nonce length = %d; want %d", len(decoded), len(nonce))
	}

	for i := range nonce {
		if decoded[i] != nonce[i] {
			t.Errorf("Decoded nonce differs at position %d", i)
		}
	}
}

// TestNonceURLSafeBase64 verifies that nonce encoding uses URL-safe base64
// (required for LocalSend WebRTC protocol compatibility).
func TestNonceURLSafeBase64(t *testing.T) {
	// Generate many nonces and check none contain standard base64 chars
	for i := 0; i < 100; i++ {
		nonce, err := GenerateNonce()
		if err != nil {
			t.Fatalf("GenerateNonce failed: %v", err)
		}

		encoded := EncodeNonce(nonce)

		// URL-safe base64 uses '-' and '_' instead of '+' and '/'
		if strings.Contains(encoded, "+") {
			t.Errorf("Encoded nonce contains '+' (should use URL-safe base64): %s", encoded)
		}
		if strings.Contains(encoded, "/") {
			t.Errorf("Encoded nonce contains '/' (should use URL-safe base64): %s", encoded)
		}
		// Should not have padding
		if strings.Contains(encoded, "=") {
			t.Errorf("Encoded nonce contains '=' padding (should use no-padding base64): %s", encoded)
		}
	}
}

// TestDecodeURLSafeNonce tests decoding of an actual nonce received from LocalSend.
func TestDecodeURLSafeNonce(t *testing.T) {
	// Real nonce from official LocalSend app (contains URL-safe chars)
	officialNonce := "xLJNxeKwfKvx1IYqVE_cYAUF54R547Aq6C_E_p_eilk"

	decoded, err := DecodeNonce(officialNonce)
	if err != nil {
		t.Fatalf("Failed to decode official nonce: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("Decoded nonce length = %d; want 32", len(decoded))
	}

	// Re-encode should match original
	reencoded := EncodeNonce(decoded)
	if reencoded != officialNonce {
		t.Errorf("Re-encoded nonce = %q; want %q", reencoded, officialNonce)
	}
}

