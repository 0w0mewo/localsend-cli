package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// GenerateSelfSignedCert generates a self-signed certificate for TLS.
// Returns certificate PEM, private key PEM, and error.
func GenerateSelfSignedCert(key *SigningKey) (certPEM, keyPEM string, err error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "LocalSend User",
			Organization: []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.publicKey, key.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	privBytes, err := x509.MarshalPKCS8PrivateKey(key.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	return string(certPEMBlock), string(keyPEMBlock), nil
}

// PublicKeyFromCertDER extracts the public key from a DER-encoded certificate.
func PublicKeyFromCertDER(der []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return pubKeyBytes, nil
}

// FingerprintFromCertDER generates a SHA256 fingerprint from a certificate.
func FingerprintFromCertDER(der []byte) string {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return ""
	}

	digest := createDigestFromDER(pubKeyBytes, nil)
	return EncodeNonce(digest)
}
