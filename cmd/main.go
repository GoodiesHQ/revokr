package main

import (
	"context"
	"fmt"
	"os"

	"github.com/goodieshq/revokr/pkg/crl"
	"github.com/goodieshq/revokr/pkg/utils"
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
				Usage:   "Output file to write results to (default: stdout)",
			},
			&cli.StringFlag{
				Name:  "number",
				Usage: "CRL number to use. If --extend/-x is used and finds a valid CRL with a positive CRL number, this value is ignored",
				Value: "1",
			},
			&cli.StringSliceFlag{
				Name:    "extend",
				Aliases: []string{"x"},
				Usage:   "Path to one or more existing CRLs to copy and extend. The new CRL inherets all revoked serials from each and increments the CRL number accordingly (ignores --number/-n flag)",
			},
			&cli.StringFlag{
				Name:    "crt",
				Aliases: []string{"c"},
				Usage:   "issuing certificate file",
			},
			&cli.StringFlag{
				Name:    "key",
				Aliases: []string{"k"},
				Usage:   "issuing certificate private key file",
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
				Aliases: []string{"t"},
				Usage:   "set the 'this update' time for the CRL (RFC3339 format). If not specified, uses the NotBefore time of the issuing certificate",
				Validator: func(s string) error {
					_, err := utils.ParseTime(s)
					if err != nil {
						return cli.Exit(fmt.Sprintf("invalid time format for --this-update/-t: %v", err), 1)
					}
					return nil
				},
			},
			&cli.StringFlag{
				Name:    "next-update",
				Aliases: []string{"n"},
				Usage:   "set the 'next update' time for the CRL (RFC3339 format). If not specified, uses the NotAfter time of the issuing certificate",
				Validator: func(s string) error {
					_, err := utils.ParseTime(s)
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
		// log.Fatal().Err(err).Msg("application error")
	}
}

func cmdCreate(_ context.Context, c *cli.Command) error {
	var serialsInclude, serialsIgnore []string
	var err error

	serialsPath := c.String("serials")
	if serialsPath != "" {
		serialsInclude, err = utils.ReadSerialNumbersFromFile(serialsPath)
		if err != nil {
			return cli.Exit(fmt.Sprintf("failed to read serials file: %v", err), 1)
		}
	}

	ignorePath := c.String("ignore")
	if ignorePath != "" {
		serialsIgnore, err = utils.ReadSerialNumbersFromFile(c.String("ignore"))
		if err != nil {
			return cli.Exit(fmt.Sprintf("failed to read ignore file: %v", err), 1)
		}
	}

	issuerCrtPath := c.String("crt")
	issuerKeyPath := c.String("key")

	if issuerCrtPath == "" || issuerKeyPath == "" {
		return cli.Exit("issuer certificate and key paths must be specified with --crt/-c and --key/-k", 1)
	}

	crt, err := utils.ParseCertificate(issuerCrtPath)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse issuer certificate: %v", err), 1)
	}

	key, err := utils.ParsePrivateSigner(issuerKeyPath)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse issuer private key: %v", err), 1)
	}

	updateThisStr, err := utils.ParseTime(c.String("this-update"))
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse this-update time: %v", err), 1)
	}

	updateNextStr, err := utils.ParseTime(c.String("next-update"))
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to parse next-update time: %v", err), 1)
	}

	extendPaths := c.StringSlice("extend")
	crlNumber, entries, err := crl.ExtractRevocationEntries(serialsIgnore, extendPaths...)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to extract revocation entries from existing CRLs: %v", err), 1)
	}

	if crlNumber == -1 {
		crlNumber = int64(c.Uint64("number"))
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
