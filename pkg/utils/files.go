package utils

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// TryParsePEM attempts to read and decode a PEM file. If the file is not PEM encoded, it returns the raw data.
func TryParsePEM(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// attempt to decode as PEM, but return raw data if not PEM encoded
	if block, _ := pem.Decode(data); block != nil {
		return block.Bytes, nil
	}

	return data, nil
}

// ParseCertificate reads and parses an x509 certificate from the given file path.
func ParseCertificate(path string) (*x509.Certificate, error) {
	// Read and parse the issuer certificate
	crtData, err := TryParsePEM(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read issuer certificate: %w", err)
	}

	crt, err := x509.ParseCertificate(crtData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer certificate: %w", err)
	}

	return crt, nil
}

func ParsePrivateSigner(path string) (crypto.Signer, error) {
	// Read and parse the issuer private key
	keyData, err := TryParsePEM(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read issuer private key: %w", err)
	}

	var priv any

	// Try parsing as PKCS8, PKCS1, and EC private key formats
	if priv, err = x509.ParsePKCS8PrivateKey(keyData); err != nil {
		if priv, err = x509.ParsePKCS1PrivateKey(keyData); err != nil {
			if priv, err = x509.ParseECPrivateKey(keyData); err != nil {
				return nil, fmt.Errorf("failed to parse issuer private key: %w", err)
			}
		}
	}

	key, ok := priv.(crypto.Signer)
	if !ok {
		// should not happen if the key was parsed successfully
		return nil, fmt.Errorf("issuer private key is not a crypto.Signer")
	}

	return key, nil
}
