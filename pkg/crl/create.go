package crl

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type CreateCRLParams struct {
	SerialsInclude []string
	SerialsIgnore  []string
	Entries        []x509.RevocationListEntry
	OutPath        string
	OutPEM         bool
	CRLNumber      *big.Int
	ThisUpdate     time.Time
	NextUpdate     time.Time
}

func CreateCRL(crt *x509.Certificate, key crypto.Signer, params *CreateCRLParams) error {
	var thisUpdate time.Time
	if params.ThisUpdate.IsZero() {
		thisUpdate = crt.NotBefore
	} else {
		thisUpdate = params.ThisUpdate
	}

	var nextUpdate time.Time
	if params.NextUpdate.IsZero() {
		nextUpdate = crt.NotAfter
	} else {
		nextUpdate = params.NextUpdate
	}

	// Prepare revoked certificates list
	revokedCerts := params.Entries
	serialsSeen := make(map[string]struct{})
	for _, entry := range revokedCerts {
		serialsSeen[entry.SerialNumber.Text(16)] = struct{}{}
	}
	for _, serial := range params.SerialsIgnore {
		serialsSeen[serial] = struct{}{}
	}

	for _, serial := range params.SerialsInclude {
		if _, ok := serialsSeen[serial]; !ok {
			serialNum, _ := new(big.Int).SetString(serial, 16)
			revokedCerts = append(revokedCerts, x509.RevocationListEntry{
				SerialNumber:   serialNum,
				RevocationTime: thisUpdate,
			})
			serialsSeen[serial] = struct{}{}
		}
	}

	crlTemplate := &x509.RevocationList{
		Number:                    params.CRLNumber,
		SignatureAlgorithm:        crt.SignatureAlgorithm,
		RevokedCertificateEntries: revokedCerts,
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
	}

	crl, err := x509.CreateRevocationList(rand.Reader, crlTemplate, crt, key)
	if err != nil {
		return fmt.Errorf("failed to create CRL: %w", err)
	}

	var outData []byte
	if params.OutPEM {
		outData = pem.EncodeToMemory(&pem.Block{
			Type:  "X509 CRL",
			Bytes: crl,
		})
	} else {
		outData = crl
	}

	if params.OutPath == "" {
		if !params.OutPEM {
			return fmt.Errorf("output path must be specified when outputting DER format CRL")
		}
		fmt.Print(string(outData))
		return nil
	}

	err = os.WriteFile(params.OutPath, outData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write CRL to file: %w", err)
	}

	return nil
}
