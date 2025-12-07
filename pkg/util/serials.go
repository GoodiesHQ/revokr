package util

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

func DedupRevocationEntries(entries []x509.RevocationListEntry, serialsIgnore []string) []x509.RevocationListEntry {
	serialsSeen := make(map[string]struct{})
	// We don't want to include these serials in the new CRL (e.g. they may belong to expired certs)
	for _, serial := range serialsIgnore {
		serialsSeen[serial] = struct{}{}
	}

	var entriesDeduped []x509.RevocationListEntry
	// Now add the existing CRL revocation entries, skipping any that are in the ignore list or have already been seen
	for _, entry := range entries {
		serial := entry.SerialNumber.Text(16)
		if _, ok := serialsSeen[serial]; !ok {
			serialsSeen[serial] = struct{}{}
			entriesDeduped = append(entriesDeduped, entry)
		}
	}

	return entriesDeduped
}

func DedupSerialNumbers(entries []x509.RevocationListEntry, serialsInclude, serialsIgnore []string) []string {
	serialsSeen := make(map[string]struct{})
	var serials []string

	entries = DedupRevocationEntries(entries, serialsIgnore)

	// Start with the existing CRL revocation entries
	for _, entry := range entries {
		serialsSeen[entry.SerialNumber.Text(16)] = struct{}{}
	}

	// We don't want to include these serials in the new CRL (e.g. they may belong to expired certs)
	for _, serial := range serialsIgnore {
		serialsSeen[serial] = struct{}{}
	}

	// Now add the serials we want to include, skipping any that have already been seen
	for _, serial := range serialsInclude {
		if _, ok := serialsSeen[serial]; !ok {
			serialsSeen[serial] = struct{}{}
			serials = append(serials, serial)
		}
	}

	return serials
}

func ReadSerialNumbersFromFile(path string) ([]string, error) {
	var serials []string
	if path == "" { // no serials file provided, return empty CRL list
		return serials, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read serial numbers file: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		line := strings.ToLower(strings.TrimSpace(line))
		if line != "" {
			line = strings.TrimPrefix(line, "0x")
			_, good := new(big.Int).SetString(line, 16)
			if !good {
				log.Warn().Str("serial", line).Msg("invalid serial number format, skipping")
				continue
			}
			serials = append(serials, line)
		}
	}

	var serialsDeduped []string
	seen := make(map[string]struct{})
	for _, serial := range serials {
		if _, ok := seen[serial]; !ok {
			seen[serial] = struct{}{}
			serialsDeduped = append(serialsDeduped, serial)
		}
	}

	return serialsDeduped, nil
}
