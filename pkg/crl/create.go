package crl

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/goodieshq/revokr/pkg/util"
)

type CreateCRLParams struct {
	SerialsInclude []string
	SerialsIgnore  []string
	Entries        []x509.RevocationListEntry
	DigestPath     string
	OutPath        string
	TBS            bool
	OutPEM         bool
	CRLNumber      *big.Int
	ThisUpdate     time.Time
	NextUpdate     time.Time
}

func CreateCRL(crt *x509.Certificate, key crypto.Signer, params *CreateCRLParams) error {
	var err error

	if !params.OutPEM && params.OutPath == "" {
		return fmt.Errorf("output path must be specified when creating a DER format CRL")
	}

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

	if params.TBS {
		key, err = util.DummySigner(crt.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to create dummy signer for TBS CRL: %w", err)
		}
	}

	if key == nil {
		return fmt.Errorf("private key or TBS is required to create CRL")
	}

	// Create the CRL
	crl, err := x509.CreateRevocationList(rand.Reader, crlTemplate, crt, key)
	if err != nil {
		return fmt.Errorf("failed to create CRL: %w", err)
	}

	if params.TBS {
		crl, err = util.ExtractTBS(crl)
		if err != nil {
			return fmt.Errorf("failed to extract TBS from CRL: %w", err)
		}

		_, h, err := util.GetSignatureAlgAndHash(crt)
		if err != nil {
			return fmt.Errorf("failed to get hash for TBS CRL: %w", err)
		}

		digest := h.Sum(crl)
		if err := util.WriteDigest(params.DigestPath, digest); err != nil {
			return fmt.Errorf("failed to write TBS CRL digest: %w", err)
		}
	}

	return util.WriteCRL(params.OutPath, crl, params.OutPEM)
}
