package crl

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/goodieshq/revokr/pkg/util"
)

type AssembleCRLParams struct {
	OutPath string
	OutPEM  bool
}

func AssembleCRL(crt *x509.Certificate, tbs asn1.RawValue, signature []byte, params *AssembleCRLParams) error {
	sigAlgo, _, err := util.GetSignatureAlgAndHash(crt)
	if err != nil {
		return fmt.Errorf("failed to get signature algorithm: %w", err)
	}

	if len(signature) == 0 {
		return fmt.Errorf("signature data is empty")
	}

	rcrl := &util.RawCRL{
		TBS:                tbs,
		SignatureAlgorithm: sigAlgo,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	crl, err := asn1.Marshal(*rcrl)
	if err != nil {
		return fmt.Errorf("failed to marshal assembled CRL: %w", err)
	}

	return util.WriteCRL(params.OutPath, crl, params.OutPEM)
}
