package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// DummySigner generates a temp private key matching the type of the provided public key.
func DummySigner(pub crypto.PublicKey) (crypto.Signer, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		priv, err := ecdsa.GenerateKey(k.Curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		return priv, nil
	case *rsa.PublicKey:
		size := (k.N.BitLen() + 7) / 8 // in bytes
		priv, err := rsa.GenerateKey(rand.Reader, size*8)
		if err != nil {
			return nil, err
		}
		return priv, nil
	case *ed25519.PublicKey:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return priv, nil
	}
	return nil, fmt.Errorf("unsupported public key type: %T", pub)
}
