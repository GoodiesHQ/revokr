package crl

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/goodieshq/revokr/pkg/util"
)

type AssembleCRLParams struct {
	Crt       *x509.Certificate
	TBS       *asn1.RawValue
	Signature []byte
	OutPath   string
	OutPEM    bool
}

func AssembleCRL(crt *x509.Certificate, params *AssembleCRLParams) error {
	sigAlgo, _, err := util.GetSignatureAlgAndHash(crt)
	if err != nil {
		return fmt.Errorf("failed to get signature algorithm: %w", err)
	}

	if params.TBS == nil {
		return fmt.Errorf("TBS data must be provided")
	}

	if params.Signature == nil {
		return fmt.Errorf("signature data must be provided")
	}

	rcrl := &util.RawCRL{
		TBS:                *params.TBS,
		SignatureAlgorithm: sigAlgo,
		SignatureValue: asn1.BitString{
			Bytes:     params.Signature,
			BitLength: len(params.Signature) * 8,
		},
	}

	crl, err := asn1.Marshal(*rcrl)
	if err != nil {
		return fmt.Errorf("failed to marshal assembled CRL: %w", err)
	}

	return util.WriteCRL(params.OutPath, crl, params.OutPEM)
}
