package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const rsaKeyBits = 2048

// GenerateRSAKeyPair generates a new RSA key pair and returns PEM-encoded strings.
func GenerateRSAKeyPair() (privatePEM, publicPEM string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	privatePEM = string(pem.EncodeToMemory(privBlock))

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	publicPEM = string(pem.EncodeToMemory(pubBlock))

	return privatePEM, publicPEM, nil
}

// ParseRSAPrivateKey parses a PEM-encoded RSA private key.
func ParseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ParseRSAPublicKey parses a PEM-encoded RSA public key.
func ParseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}
