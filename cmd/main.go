package main

import (
	"context"
	"crypto"
	"fmt"
	"math/big"
	"os"

	"github.com/goodieshq/revokr/pkg/crl"
	"github.com/goodieshq/revokr/pkg/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

var app *cli.Command

const Version = "dev"

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out: os.Stderr,
	}).Level(zerolog.InfoLevel)

	cli.VersionPrinter = func(c *cli.Command) {
		fmt.Printf("%s\n", c.Version)
	}

	app = &cli.Command{
		Name:    "revokr",
		Usage:   "A tool for assisting in the management of certificate revocation lists",
		Version: Version,
		Commands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Create a new CRL or extend an existing CRL with additional revocation entries",
				Action: func(ctx context.Context, c *cli.Command) error {
					return cmdCreate(ctx, c)
				},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "number",
						Usage:   "CRL number to use (in decimel). If not specified, defaults to 1 or increments the highest CRL number found in any extended CRLs.",
						Aliases: []string{"n"},
						Value:   "",
						Validator: func(s string) error {
							if _, ok := new(big.Int).SetString(s, 10); !ok {
								return cli.Exit("invalid CRL number, must be a valid decimal number", 1)
							}
							return nil
						},
					},
					&cli.StringSliceFlag{
						Name:    "extend",
						Aliases: []string{"x"},
						Usage:   "Path to existing CRL to copy and extend. The new CRL inherets all revoked serials except those in the ignore list.",
					},
					&cli.StringFlag{
						Name:    "key",
						Aliases: []string{"k"},
						Usage:   "Path to the issuing certificate private key file.",
					},
					&cli.StringFlag{
						Name:    "password",
						Aliases: []string{"p"},
						Usage:   "Password for the issuing certificate private key, if it is encrypted.",
					},
					&cli.BoolFlag{
						Name:    "password-prompt",
						Usage:   "Prompt for the password for the issuing certificate private key, if it is encrypted. (overrides --password/-p)",
						Aliases: []string{"P"},
					},
					&cli.StringFlag{
						Name:    "serials",
						Aliases: []string{"s"},
						Usage:   "file containing list of serial numbers (in hexadecimal) to include in the CRL",
					},
					&cli.StringFlag{
						Name:    "ignore",
						Aliases: []string{"i"},
						Usage:   "file containing list of serial numbers (in hexadecimal) to ignore when creating the CRL",
					},
					&cli.StringFlag{
						Name:    "this-update",
						Aliases: []string{"tu", "T"},
						Usage:   "Set the 'this update' time for the CRL (RFC3339 format). If not specified, uses the NotBefore time of the issuing certificate.",
						Validator: func(s string) error {
							_, err := util.ParseTime(s)
							if err != nil {
								return cli.Exit(fmt.Sprintf("invalid time format for --this-update/-t: %v", err), 1)
							}
							return nil
						},
					},
					&cli.StringFlag{
						Name:    "next-update",
						Aliases: []string{"nu", "N"},
						Usage:   "Set the 'next update' time for the CRL (RFC3339 format). If not specified, uses the NotAfter time of the issuing certificate",
						Validator: func(s string) error {
							_, err := util.ParseTime(s)
							if err != nil {
								return cli.Exit(fmt.Sprintf("invalid time format for --next-update/-n: %v", err), 1)
							}
							return nil
						},
					},
					&cli.BoolFlag{
						Name:    "to-be-signed",
						Aliases: []string{"tbs", "t"},
						Usage:   "Output the 'to be signed' portion of the CRL in PEM format to stdout instead of creating a signed CRL.",
					},
					&cli.StringFlag{
						Name:    "digest",
						Aliases: []string{"s"},
						Usage:   "Target file to output the digest signature of the TBS CRL when using --to-be-signed/--tbs.",
					},
				},
			},
			{
				Name:  "assemble",
				Usage: "Assemble a CRL from a Cert, TBS CRL, and a signature from the issuing CA.",
				Action: func(ctx context.Context, c *cli.Command) error {
					return cmdAssemble(ctx, c)
				},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "to-be-signed",
						Aliases: []string{"tbs", "t"},
						Usage:   "The TBS CRL file to use for assembling the final CRL.",
					},
					&cli.StringFlag{
						Name:    "signature",
						Aliases: []string{"s"},
						Usage:   "The signature file to use for assembling the final CRL.",
					},
				},
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "out",
				Aliases: []string{"o"},
				Usage:   "Output file path to write the generated CRL to.",
			},
			&cli.StringFlag{
				Name:    "crt",
				Aliases: []string{"c"},
				Usage:   "Path to the issuing certificate file (used for generation and assembly from TBS).",
			},
			&cli.BoolFlag{
				Name:  "pem",
				Usage: "output the CRL in PEM format. If not set, the CRL will be output in DER format",
			},
		},
	}
}

func main() {
	if err := app.Run(context.Background(), os.Args); err != nil {
		if errExit, ok := err.(cli.ExitCoder); ok {
			if Version == "dev" {
				if errExit.ExitCode() != 0 {
					os.Exit(0)
				}
			}
			os.Exit(errExit.ExitCode())
		}
		log.Fatal().Err(err).Msg("application error")
	}
}

func cmdAssemble(_ context.Context, c *cli.Command) error {
	tbsPath := c.String("to-be-signed")
	if tbsPath == "" {
		return cli.Exit("TBS CRL path must be specified with --to-be-signed/-t", 1)
	}
	tbs, err := util.ParseTBSCRL(tbsPath)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse TBS CRL: %v", err), 1)
	}

	signaturePath := c.String("signature")
	if signaturePath == "" {
		return cli.Exit("signature path must be specified with --signature/-s", 1)
	}
	signature, err := util.ReadSignatureFile(signaturePath)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to read signature file: %v", err), 1)
	}

	issuerCrtPath := c.String("crt")
	if issuerCrtPath == "" {
		return cli.Exit("issuer certificate path must be specified with --crt/-c", 1)
	}

	crt, err := util.ParseCertificate(issuerCrtPath)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse issuer certificate: %v", err), 1)
	}

	err = crl.AssembleCRL(crt, *tbs, signature, &crl.AssembleCRLParams{
		OutPath: c.String("out"),
		OutPEM:  c.Bool("pem"),
	})
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to assemble CRL: %v", err), 1)
	}

	return nil
}

func cmdCreate(_ context.Context, c *cli.Command) error {
	var serialsInclude, serialsIgnore []string
	var err error

	// Check if TBS output is requested
	tbs := c.Bool("to-be-signed")
	digestPath := c.String("digest")
	if tbs && digestPath == "" {
		return cli.Exit("target digest path must be specified when creating a TBS CRL", 1)
	}

	// Read serial numbers of certificates to include in the CRL
	serialsPath := c.String("serials")
	if serialsPath != "" {
		serialsInclude, err = util.ReadSerialNumbersFromFile(serialsPath)
		if err != nil {
			return cli.Exit(fmt.Sprintf("failed to read serials file: %v", err), 1)
		}
	}

	// Read serial numbers of certificates to ignore in the CRL (removes from extended CRLs)
	ignorePath := c.String("ignore")
	if ignorePath != "" {
		serialsIgnore, err = util.ReadSerialNumbersFromFile(c.String("ignore"))
		if err != nil {
			return cli.Exit(fmt.Sprintf("failed to read ignore file: %v", err), 1)
		}
	}

	// Parse issuer certificate and private key
	issuerCrtPath := c.String("crt")
	issuerKeyPath := c.String("key")

	if tbs && issuerKeyPath != "" {
		return cli.Exit("issuer private key should not be specified when creating a TBS CRL", 1)
	}

	if issuerCrtPath == "" {
		return cli.Exit("issuer certificate path must be specified with --crt/-c", 1)
	}

	if !tbs && issuerKeyPath == "" {
		return cli.Exit("issuer private key path must be specified with --key/-k", 1)
	}

	crt, err := util.ParseCertificate(issuerCrtPath)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse issuer certificate: %v", err), 1)
	}

	password := c.String("password")
	passwordPrompt := c.Bool("password-prompt")
	if tbs && (password != "" || passwordPrompt) {
		return cli.Exit("password should not be specified when creating a TBS CRL", 1)
	}

	if passwordPrompt {
		password, err = util.PromptPassword("Enter the private key password")
		if err != nil {
			return cli.Exit(fmt.Sprintf("failed to read private key password: %v", err), 1)
		}
	}

	if tbs {
		password = "" // no password needed when not signing
	}

	var key crypto.Signer = nil

	if !tbs {
		key, err = util.ParsePrivateSigner(issuerKeyPath, password)
		if err != nil {
			return cli.Exit(fmt.Sprintf("failed to parse issuer private key: %v", err), 1)
		}

		if key == nil {
			return cli.Exit("issuer private key could not be parsed", 1)
		}

		// Verify that the provided certificate and private key actually match
		if err := util.VerifyCrtKeyMatch(crt, key); err != nil {
			return cli.Exit(fmt.Sprintf("issuer certificate and private key do not match: %v", err), 1)
		}
	}

	// Parse this-update and next-update times

	updateThisStr, err := util.ParseTime(c.String("this-update"))
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse this-update time: %v", err), 1)
	}

	updateNextStr, err := util.ParseTime(c.String("next-update"))
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse next-update time: %v", err), 1)
	}

	// Extract existing revocation entries from CRLs, ignore serials in the ignore list
	extendPaths := c.StringSlice("extend")
	crlNumber, entries, err := crl.ExtractRevocationEntries(serialsIgnore, extendPaths...)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to extract revocation entries from existing CRLs: %v", err), 1)
	}

	// Determine CRL number to use, either from flag or by incrementing existing highest number
	var numberStr = c.String("number")
	if numberStr != "" {
		// if a CRL number is explicitly provided, use that
		crlNumber, _ = new(big.Int).SetString(numberStr, 10)
	} else if crlNumber == nil || crlNumber.Cmp(big.NewInt(-1)) == 0 {
		// no valid CRL number found in extended CRLs, use default of 1
		crlNumber = big.NewInt(1)
	} else {
		// increment the highest CRL number found in the extended CRLs
		crlNumber.Add(crlNumber, big.NewInt(1))
	}

	// Create the CRL
	err = crl.CreateCRL(crt, key, &crl.CreateCRLParams{
		SerialsInclude: serialsInclude,
		SerialsIgnore:  serialsIgnore,
		Entries:        entries,
		TBS:            tbs,
		DigestPath:     digestPath,
		OutPath:        c.String("out"),
		OutPEM:         c.Bool("pem"),
		CRLNumber:      crlNumber,
		ThisUpdate:     updateThisStr,
		NextUpdate:     updateNextStr,
	})
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to create CRL: %v", err), 1)
	}

	return nil
}
