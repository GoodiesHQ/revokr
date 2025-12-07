package util

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/youmark/pkcs8"
)

// TryParsePEM attempts to read and decode a PEM file. If the file is not PEM encoded, it returns the raw data.
func TryParsePEM(path string) (*pem.Block, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// attempt to decode as PEM, but return raw data if not PEM encoded
	if block, _ := pem.Decode(data); block != nil {
		return block, nil
	}

	return &pem.Block{
		Type:    "",
		Bytes:   data,
		Headers: map[string]string{},
	}, nil
}

// ParseCertificate reads and parses an x509 certificate from the given file path.
func ParseCertificate(path string) (*x509.Certificate, error) {
	// Read and parse the issuer certificate
	block, err := TryParsePEM(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read issuer certificate: %w", err)
	}

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer certificate: %w", err)
	}

	return crt, nil
}

// isLegacyEncryptedPEMBlock checks if a PEM block is encrypted using the legacy PEM encryption format.
func isLegacyEncryptedPEMBlock(block *pem.Block) bool {
	if block == nil {
		return false
	}

	if pt, ok := block.Headers["Proc-Type"]; ok {
		return strings.Contains(pt, "ENCRYPTED")
	}

	return false
}

func ParsePrivateSigner(path, password string) (crypto.Signer, error) {
	// Read and parse the issuer private key
	block, err := TryParsePEM(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read issuer private key: %w", err)
	}

	var (
		der  []byte            = block.Bytes
		priv crypto.PrivateKey = nil
	)

	if isLegacyEncryptedPEMBlock(block) {
		log.Warn().Msg("legacy PEM encryption detected; consider using PKCS8 format for better security")
		if password == "" {
			return nil, fmt.Errorf("issuer private key is encrypted but no password was provided")
		}

		der, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt issuer private key: %w", err)
		}
	}

	if block.Type != "" && strings.Contains(block.Type, "ENCRYPTED") {
		if password == "" {
			return nil, fmt.Errorf("issuer private key is encrypted but no password was provided")
		}

		p, err := pkcs8.ParsePKCS8PrivateKey(der, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt issuer private key: %w", err)
		}
		priv = p
	} else {
		var errPKCS8 error

		if password != "" {
			// assume the key is encrypted PKCS8 if a password is provided
			p, err := pkcs8.ParsePKCS8PrivateKey(der, []byte(password))
			if err == nil {
				priv = p
			} else {
				errPKCS8 = err
			}
		} else {
			// try parsing as unencrypted PKCS8 first
			p, err := pkcs8.ParsePKCS8PrivateKey(der, nil)
			if err == nil {
				priv = p
			} else {
				errPKCS8 = err
			}
		}

		if priv == nil {
			if rsaKey, err := x509.ParsePKCS1PrivateKey(der); err == nil {
				priv = rsaKey
			} else if ecKey, err := x509.ParseECPrivateKey(der); err == nil {
				priv = ecKey
			} else if errPKCS8 != nil {
				return nil, fmt.Errorf("failed to parse issuer private key: %w", errPKCS8)
			} else {
				return nil, fmt.Errorf("failed to parse issuer private key: unknown format")
			}
		}
	}

	if priv == nil {
		return nil, fmt.Errorf("failed to parse issuer private key: unknown format")
	}

	key, ok := priv.(crypto.Signer)
	if !ok {
		// should not happen if the key was parsed successfully
		return nil, fmt.Errorf("issuer private key is not a crypto.Signer")
	}

	return key, nil
}
