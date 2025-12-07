package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

func VerifyCrtKeyMatch(crt *x509.Certificate, key crypto.Signer) error {
	if crt == nil {
		return fmt.Errorf("certificate is nil")
	}
	if key == nil {
		return fmt.Errorf("private key is nil")
	}

	keyPub := key.Public()

	switch kp := keyPub.(type) {
	case *rsa.PublicKey:
		cp, ok := crt.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not RSA")
		}
		if kp.N.Cmp(cp.N) != 0 || kp.E != cp.E {
			return fmt.Errorf("RSA public key in certificate does not match private key")
		}
	case *ecdsa.PublicKey:
		cp, ok := crt.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not ECDSA")
		}
		if kp.X.Cmp(cp.X) != 0 || kp.Y.Cmp(cp.Y) != 0 {
			return fmt.Errorf("ECDSA public key in certificate does not match private key")
		}
	case *ed25519.PublicKey:
		cp, ok := crt.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not Ed25519")
		}
		if !kp.Equal(cp) {
			return fmt.Errorf("Ed25519 public key in certificate does not match private key")
		}
	default:
		return fmt.Errorf("unsupported public key type for verification")
	}
	return nil
}
