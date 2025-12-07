package main

import (
	"context"
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
		Usage:   "A tool for assisting the management of revocation lists for certificates",
		Version: Version,
		Action: func(ctx context.Context, c *cli.Command) error {
			return cmdCreate(ctx, c)
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "out",
				Aliases: []string{"o"},
				Usage:   "Output file path to write the generated CRL to.",
			},
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
				Name:    "crt",
				Aliases: []string{"c"},
				Usage:   "Path to the issuing certificate file.",
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
			&cli.BoolFlag{
				Name:  "pem",
				Usage: "output the CRL in PEM format. If not set, the CRL will be output in DER format",
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
		},
	}
}

func main() {
	if err := app.Run(context.Background(), os.Args); err != nil {
		if errExit, ok := err.(cli.ExitCoder); ok {
			os.Exit(errExit.ExitCode())
		}
		log.Fatal().Err(err).Msg("application error")
	}
}

func cmdCreate(_ context.Context, c *cli.Command) error {
	var serialsInclude, serialsIgnore []string
	var err error

	serialsPath := c.String("serials")
	if serialsPath != "" {
		serialsInclude, err = util.ReadSerialNumbersFromFile(serialsPath)
		if err != nil {
			return cli.Exit(fmt.Sprintf("failed to read serials file: %v", err), 1)
		}
	}

	ignorePath := c.String("ignore")
	if ignorePath != "" {
		serialsIgnore, err = util.ReadSerialNumbersFromFile(c.String("ignore"))
		if err != nil {
			return cli.Exit(fmt.Sprintf("failed to read ignore file: %v", err), 1)
		}
	}

	issuerCrtPath := c.String("crt")
	issuerKeyPath := c.String("key")

	if issuerCrtPath == "" || issuerKeyPath == "" {
		return cli.Exit("issuer certificate and key paths must be specified with --crt/-c and --key/-k", 1)
	}

	crt, err := util.ParseCertificate(issuerCrtPath)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse issuer certificate: %v", err), 1)
	}

	password := c.String("password")
	if c.Bool("password-prompt") {
		password, err = util.PromptPassword("Enter the private key password")
	}

	key, err := util.ParsePrivateSigner(issuerKeyPath, password)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse issuer private key: %v", err), 1)
	}

	if err := util.VerifyCrtKeyMatch(crt, key); err != nil {
		return cli.Exit(fmt.Sprintf("issuer certificate and private key do not match: %v", err), 1)
	}

	updateThisStr, err := util.ParseTime(c.String("this-update"))
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse this-update time: %v", err), 1)
	}

	updateNextStr, err := util.ParseTime(c.String("next-update"))
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse next-update time: %v", err), 1)
	}

	extendPaths := c.StringSlice("extend")
	crlNumber, entries, err := crl.ExtractRevocationEntries(serialsIgnore, extendPaths...)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to extract revocation entries from existing CRLs: %v", err), 1)
	}

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

	outPath := c.String("out")
	pem := c.Bool("pem")
	if !pem && outPath == "" {
		return cli.Exit("output path must be specified when outputting DER format CRL", 1)
	}

	err = crl.CreateCRL(crt, key, &crl.CreateCRLParams{
		SerialsInclude: serialsInclude,
		SerialsIgnore:  serialsIgnore,
		Entries:        entries,
		OutPath:        c.String("out"),
		OutPEM:         pem,
		CRLNumber:      crlNumber,
		ThisUpdate:     updateThisStr,
		NextUpdate:     updateNextStr,
	})
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to create CRL: %v", err), 1)
	}

	return nil
}
