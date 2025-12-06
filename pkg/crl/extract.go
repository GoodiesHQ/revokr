package crl

import (
	"crypto/x509"

	"github.com/goodieshq/revokr/pkg/utils"
	"github.com/rs/zerolog/log"
)

// ExtractRevocationEntries reads revocation entries from the provided CRL files,
// ignoring any serial numbers specified in the ignore list. It returns the highest
// CRL number found in the paths and a deduplicated list of revocation entries.
func ExtractRevocationEntries(ignore []string, paths ...string) (int64, []x509.RevocationListEntry, error) {
	var crlNumber int64 = -1

	serialsSeen := make(map[string]struct{})
	for _, serial := range ignore {
		serialsSeen[serial] = struct{}{}
	}

	var entries []x509.RevocationListEntry

	for _, path := range paths {
		crlData, err := utils.TryParsePEM(path)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("failed to read CRL file, skipping")
			continue
		}

		crl, err := x509.ParseRevocationList(crlData)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("failed to parse revocation list, skipping")
			continue
		}

		if crl.Number.Int64() > crlNumber {
			crlNumber = crl.Number.Int64()
		}

		for _, entry := range crl.RevokedCertificateEntries {
			serial := entry.SerialNumber.Text(16)
			if _, ok := serialsSeen[serial]; !ok {
				serialsSeen[serial] = struct{}{}
				entries = append(entries, entry)
			}
		}
	}

	return crlNumber, entries, nil
}
