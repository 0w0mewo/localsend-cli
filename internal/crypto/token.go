package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SigningKey wraps an Ed25519 private key for token generation.
type SigningKey struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// VerifyingKey is an interface for token verification.
type VerifyingKey interface {
	Verify(msg, signature []byte) error
	ToDER() ([]byte, error)
	SignatureMethod() string
}

// Ed25519VerifyingKey implements VerifyingKey for Ed25519.
type Ed25519VerifyingKey struct {
	publicKey ed25519.PublicKey
}

// RsaPssVerifyingKey implements VerifyingKey for RSA-PSS.
// This is used by some LocalSend clients that use RSA keys instead of Ed25519.
type RsaPssVerifyingKey struct {
	publicKey *rsa.PublicKey
}

// GenerateKeyPair creates a new Ed25519 key pair for token signing.
func GenerateKeyPair() (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return &SigningKey{
		privateKey: priv,
		publicKey:  pub,
	}, nil
}

// PublicKey returns the public key component.
func (k *SigningKey) PublicKey() ed25519.PublicKey {
	return k.publicKey
}

// ToVerifyingKey returns a VerifyingKey for this signing key.
func (k *SigningKey) ToVerifyingKey() VerifyingKey {
	return &Ed25519VerifyingKey{publicKey: k.publicKey}
}

// GenerateTokenTimestamp generates a token using current Unix timestamp as salt.
// Format: sha256.{hash_base64}.{salt_base64}.ed25519.{signature_base64}
func (k *SigningKey) GenerateTokenTimestamp() (string, error) {
	salt := make([]byte, 8)
	binary.LittleEndian.PutUint64(salt, uint64(time.Now().Unix()))
	return k.GenerateToken(salt)
}

// GenerateToken generates a signed token with the given salt.
// Format: sha256.{hash_base64}.{salt_base64}.ed25519.{signature_base64}
func (k *SigningKey) GenerateToken(salt []byte) (string, error) {
	// Create digest: SHA256(publicKeyDER || salt)
	// LocalSend protocol requires SPKI (PKIX) DER format for hashing.
	pubKeyDER, err := x509.MarshalPKIXPublicKey(k.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key to DER: %w", err)
	}
	digest := createDigestFromDER(pubKeyDER, salt)

	// Sign the digest
	signature := ed25519.Sign(k.privateKey, digest)

	// Encode components using URL-safe base64 (matches official LocalSend)
	hashBase64 := base64.RawURLEncoding.EncodeToString(digest)
	saltBase64 := base64.RawURLEncoding.EncodeToString(salt)
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("sha256.%s.%s.ed25519.%s", hashBase64, saltBase64, signatureBase64), nil
}

// GenerateTokenWithNonce generates a token using the provided nonce as salt.
// This is used in WebRTC authentication where both peers exchange nonces.
func (k *SigningKey) GenerateTokenWithNonce(nonce []byte) (string, error) {
	return k.GenerateToken(nonce)
}

// VerifyTokenTimestamp verifies a token that was generated with a timestamp salt.
// Returns error if token is invalid or expired (older than 1 hour).
func VerifyTokenTimestamp(publicKey VerifyingKey, token string) error {
	return VerifyToken(publicKey, token, func(salt []byte) error {
		if len(salt) != 8 {
			return errors.New("invalid salt length for timestamp token")
		}
		timestamp := binary.LittleEndian.Uint64(salt)
		now := uint64(time.Now().Unix())
		if now-timestamp > 3600 { // 1 hour
			return errors.New("token timestamp expired")
		}
		return nil
	})
}

// VerifyTokenNonce verifies a token was generated with the expected nonce.
func VerifyTokenNonce(publicKey VerifyingKey, token string, expectedNonce []byte) error {
	return VerifyToken(publicKey, token, func(salt []byte) error {
		if len(salt) != len(expectedNonce) {
			return errors.New("nonce length mismatch")
		}
		for i := range salt {
			if salt[i] != expectedNonce[i] {
				return errors.New("nonce mismatch")
			}
		}
		return nil
	})
}

// VerifyToken verifies a token with a custom salt validator.
func VerifyToken(publicKey VerifyingKey, token string, validateSalt func([]byte) error) error {
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return errors.New("invalid token structure: expected 5 parts")
	}

	hashMethod := parts[0]
	hashBase64 := parts[1]
	saltBase64 := parts[2]
	signMethod := parts[3]
	signatureBase64 := parts[4]

	if hashMethod != "sha256" {
		return fmt.Errorf("unsupported hash method: %s", hashMethod)
	}

	if signMethod != publicKey.SignatureMethod() {
		return fmt.Errorf("signature method mismatch: expected %s, got %s", publicKey.SignatureMethod(), signMethod)
	}

	// Decode salt and validate
	salt, err := base64.RawURLEncoding.DecodeString(saltBase64)
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}
	if err := validateSalt(salt); err != nil {
		return err
	}

	// Recreate digest from public key and salt
	pubKeyDER, err := publicKey.ToDER()
	if err != nil {
		return fmt.Errorf("failed to get public key DER: %w", err)
	}
	expectedDigest := createDigestFromDER(pubKeyDER, salt)

	// Verify hash matches
	expectedHashBase64 := base64.RawURLEncoding.EncodeToString(expectedDigest)
	if expectedHashBase64 != hashBase64 {
		return errors.New("hash mismatch")
	}

	// Decode and verify signature
	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if err := publicKey.Verify(expectedDigest, signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// ExtractSignatureMethod extracts the signature method from a token.
func ExtractSignatureMethod(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

// createDigest creates SHA256(publicKey || salt).
// Deprecated: use createDigestFromDER which uses SPKI format required by protocol.
func createDigest(publicKey ed25519.PublicKey, salt []byte) []byte {
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(publicKey)
	return createDigestFromDER(pubKeyDER, salt)
}

// createDigestFromDER creates SHA256(publicKeyDER || salt).
func createDigestFromDER(publicKeyDER, salt []byte) []byte {
	h := sha256.New()
	h.Write(publicKeyDER)
	h.Write(salt)
	return h.Sum(nil)
}

// Ed25519VerifyingKey implementation

func (k *Ed25519VerifyingKey) Verify(msg, signature []byte) error {
	if !ed25519.Verify(k.publicKey, msg, signature) {
		return errors.New("ed25519 signature verification failed")
	}
	return nil
}

func (k *Ed25519VerifyingKey) ToDER() ([]byte, error) {
	// LocalSend's Ed25519 public keys in token hashes use SPKI (PKIX) DER format.
	return x509.MarshalPKIXPublicKey(k.publicKey)
}

func (k *Ed25519VerifyingKey) SignatureMethod() string {
	return "ed25519"
}

// RsaPssVerifyingKey implementation

func (k *RsaPssVerifyingKey) Verify(msg, signature []byte) error {
	// RSA-PSS uses SHA-256 for hashing the message
	hashed := sha256.Sum256(msg)
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	if err := rsa.VerifyPSS(k.publicKey, crypto.SHA256, hashed[:], signature, opts); err != nil {
		return errors.New("rsa-pss signature verification failed")
	}
	return nil
}

func (k *RsaPssVerifyingKey) ToDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.publicKey)
}

func (k *RsaPssVerifyingKey) SignatureMethod() string {
	return "rsa-pss"
}

// ParsePublicKey parses a public key for verification.
func ParsePublicKey(keyBytes []byte, kind string) (VerifyingKey, error) {
	switch kind {
	case "ed25519":
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 public key size: %d", len(keyBytes))
		}
		return &Ed25519VerifyingKey{publicKey: keyBytes}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kind)
	}
}

// ParsePublicKeyPEM parses a public key from a PEM string.
func ParsePublicKeyPEM(pemStr string) (VerifyingKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// LocalSend's Ed25519 public keys in PEM are PKIX format
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	switch v := pub.(type) {
	case ed25519.PublicKey:
		return &Ed25519VerifyingKey{publicKey: v}, nil
	case *rsa.PublicKey:
		return &RsaPssVerifyingKey{publicKey: v}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type in PEM: %T", pub)
	}
}
