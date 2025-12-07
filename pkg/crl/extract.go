package crl

import (
	"crypto/x509"
	"math/big"

	"github.com/goodieshq/revokr/pkg/util"
	"github.com/rs/zerolog/log"
)

// ExtractRevocationEntries reads revocation entries from the provided CRL files,
// ignoring any serial numbers specified in the ignore list. It returns the highest
// CRL number found in the paths and a deduplicated list of revocation entries.
// Returns -1 as crlNumber if no valid CRL number is found.
func ExtractRevocationEntries(ignore []string, paths ...string) (*big.Int, []x509.RevocationListEntry, error) {
	// Initialize crlNumber to -1 to indicate no valid CRL number found yet
	var crlNumber = new(big.Int).SetInt64(-1)

	// Use a map to track seen serial numbers for deduplication
	serialsSeen := make(map[string]struct{})
	for _, serial := range ignore {
		serialsSeen[serial] = struct{}{}
	}

	// Collect revocation entries from all provided CRL files
	var entries []x509.RevocationListEntry

	// Iterate over each provided CRL file path
	for _, path := range paths {
		// Read and decode the CRL file as needed
		block, err := util.TryParsePEM(path)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("failed to read CRL file, skipping")
			continue
		}

		// Parse the CRL
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("failed to parse revocation list, skipping")
			continue
		}

		// Update the highest CRL number found
		if crl.Number.Cmp(crlNumber) > 0 {
			crlNumber = crl.Number
		}

		// Add revocation entries, deduplicating by serial number
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
