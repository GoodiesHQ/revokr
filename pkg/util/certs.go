package util

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"hash"

	"github.com/rs/zerolog/log"
)

type RawCRL struct {
	TBS                asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

func GetSignatureAlgAndHash(crt *x509.Certificate) (pkix.AlgorithmIdentifier, hash.Hash, error) {
	switch crt.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		return pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // sha256WithRSAEncryption
			Parameters: asn1.RawValue{Tag: 5},                              // NULL
		}, crypto.SHA256.New(), nil
	case x509.ECDSAWithSHA256:
		return pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, // ecdsa-with-SHA256
		}, crypto.SHA256.New(), nil
	case x509.SHA384WithRSA:
		return pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, // sha384WithRSAEncryption
			Parameters: asn1.RawValue{Tag: 5},                              // NULL
		}, crypto.SHA384.New(), nil
	case x509.ECDSAWithSHA384:
		return pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, // ecdsa-with-SHA384
		}, crypto.SHA384.New(), nil
	case x509.SHA512WithRSA:
		return pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, // sha512WithRSAEncryption
			Parameters: asn1.RawValue{Tag: 5},                              // NULL
		}, crypto.SHA512.New(), nil
	case x509.ECDSAWithSHA512:
		return pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, // ecdsa-with-SHA512
		}, crypto.SHA512.New(), nil
	default:
		return pkix.AlgorithmIdentifier{}, nil, fmt.Errorf("unsupported signature algorithm: %v", crt.SignatureAlgorithm)
	}
}

func ReadTBSFile(path string) (*asn1.RawValue, error) {
	// Read and parse the TBS CRL file
	block, err := TryParsePEM(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read TBS CRL file: %w", err)
	}

	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(block.Bytes, &tbs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TBS CRL data: %w", err)
	}
	log.Debug().Msgf("Read TBS CRL data from file %q", path)
	return &tbs, nil
}

// ExtractTBS extracts the TBS (To Be Signed) portion from a DER-encoded CRL.
func ExtractTBS(crl []byte) ([]byte, error) {
	var certList RawCRL
	if _, err := asn1.Unmarshal(crl, &certList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CRL for TBS extraction: %w", err)
	}
	log.Debug().Msg("Extracted TBS portion from CRL")
	if len(certList.TBS.FullBytes) == 0 {
		return nil, fmt.Errorf("no TBS data found in CRL")
	}
	return certList.TBS.FullBytes, nil
}

func ReadSignatureFile(path string) ([]byte, error) {
	// Read and parse the signature file
	block, err := TryParsePEM(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature file: %w", err)
	}

	// check if the data is in base64
	var b64buf = make([]byte, base64.StdEncoding.EncodedLen(len(block.Bytes)))
	n, err := base64.StdEncoding.Decode(b64buf, block.Bytes)
	if err == nil {
		log.Debug().Msgf("Decoded base64 signature data from file %q", path)
		return b64buf[:n], nil
	}

	log.Debug().Msgf("Read raw signature data from file %q", path)
	return block.Bytes, nil
}
