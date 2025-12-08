# revokr

**revokr** is a simple utility designed for offline CA's to naively create certificate revocation lists.

    NAME:
       revokr - A tool for assisting in the management of certificate revocation lists
    
    USAGE:
       revokr [global options]
    
    VERSION:
       dev
    
    GLOBAL OPTIONS:
       --out string, -o string                                    Output file path to write the generated CRL to.
       --number string, -n string                                 CRL number to use (in decimel). If not specified, defaults to 1 or increments the highest CRL number found in any extended CRLs.
       --extend string, -x string [ --extend string, -x string ]  Path to existing CRL to copy and extend. The new CRL inherets all revoked serials except those in the ignore list.
       --crt string, -c string                                    Path to the issuing certificate file.
       --key string, -k string                                    Path to the issuing certificate private key file.
       --password string, -p string                               Password for the issuing certificate private key, if it is encrypted.
       --password-prompt, -P                                      Prompt for the password for the issuing certificate private key, if it is encrypted. (overrides --password/-p)
       --serials string, -s string                                file containing list of serial numbers (in hexadecimal) to include in the CRL
       --pem                                                      output the CRL in PEM format. If not set, the CRL will be output in DER format
       --ignore string, -i string                                 file containing list of serial numbers (in hexadecimal) to ignore when creating the CRL
       --this-update string, --tu string, -T string               Set the 'this update' time for the CRL (RFC3339 format). If not specified, uses the NotBefore time of the issuing certificate.
       --next-update string, --nu string, -N string               Set the 'next update' time for the CRL (RFC3339 format). If not specified, uses the NotAfter time of the issuing certificate
       --help, -h                                                 show help
       --version, -v                                              print the version

## Notes:
**revokr** was designed to be run on Offline CA machines. It does NOT automotically pull the system time for any attributes of the CRL because it is assumed that the local clock is not reliable or synchronized. This means:

 - The *ThisUpdate* timestamp can be passed manually, but will default to the *NotBefore* attribute of the signing certificate.
 - The *NextUpdate* timestamp can be passed manually, but will default to the *NotAfter* attribute of the signing certificate.
 - If the system clock is reliable, you can use:
    `--this-update $(date -u +"%Y-%m-%dT%H:%M:%SZ")`

# Examples:

### Create empty CRL
This command will create a new, empty CRL using the default timestamps. The default CRL number will be `1`, but you can assign a numbar manually with `--number/-n`.

    revokr --crt my_ca.crt --key my_ca.pem -o my_ca.crl

### Customize Timestamps
Pass in parameters to specify the current time (this-update) and the expected next update (next-update).

    revokr --crt my_ca.crt --key my_ca.pem -o my_ca.crl --this-update "2026-01-01T00:00:00Z" --next-update "2027-01-01T00:00:00Z"

### Revoke New Serial Numbers
Serial numbers should be in **hexadecimal** with one per line. They can optionally contain a `0x` prefix.

    # cat serials.txt:
    0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa11
    0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa22
    0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa33

    revokr --crt my_ca.crt --key my_ca.pem -o my_ca.crl --serials serials.txt --this-update "2026-01-01T00:00:00Z" --next-update "2027-01-01T00:00:00Z"

This will create a CSR:

    Certificate Revocation List (CRL):
        Data:
            Valid: false
            Version: 1 (0x1)
        Signature algorithm: ECDSA-SHA256
            Issuer: 
            Last Update: 2026-01-01 00:00:00 +0000 UTC
            Next Update: 2027-01-01 00:00:00 +0000 UTC
            CRL Extensions:
                X509v3 Authority Key Identifier:
                    keyid:8C:2C:FE:25:6E:56:38:3D:73:5B:E7:50:BB:03:17:EC:21:61:AB:71
                X509v3 CRL Number:
                    1
            Revoked Certificates:
                Serial Number: 974334424887268612135789888477522013103955028497 (0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA11)
                    Revocation Date: 2026-01-01 00:00:00 +0000 UTC
                Serial Number: 974334424887268612135789888477522013103955028514 (0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA22)
                    Revocation Date: 2026-01-01 00:00:00 +0000 UTC
                Serial Number: 974334424887268612135789888477522013103955028531 (0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA33)
                    Revocation Date: 2026-01-01 00:00:00 +0000 UTC

## Extend Existing CRLs

You can extend one or more existing CRLs by passing in `--extend/-x`. You can use this parameter more than once to extend multiple CRLs. This will extract all existing entries from the CRLs provided. You can include additional serials with `--serials/-s` or remove entries by serial number with `--ignore/-i`.

Using `--extend/-x` will take the highest CRL number and increment it by 1.

    # cat serials2.txt:
    0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa44

    # cat ignore.txt
    0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa11

    revokr --crt my_ca.crt --key my_ca.pem -o my_ca2.crl -x my_ca.crl --serials serials2.txt --ignore ignore.txt --this-update "2026-01-01T00:00:00Z" --next-update "2027-01-01T00:00:00Z"

This will create a CSR:

    Certificate Revocation List (CRL):
        Data:
            Valid: false
            Version: 2 (0x2)
        Signature algorithm: ECDSA-SHA256
            Issuer: 
            Last Update: 2026-01-01 00:00:00 +0000 UTC
            Next Update: 2027-01-01 00:00:00 +0000 UTC
            CRL Extensions:
                X509v3 Authority Key Identifier:
                    keyid:8C:2C:FE:25:6E:56:38:3D:73:5B:E7:50:BB:03:17:EC:21:61:AB:71
                X509v3 CRL Number:
                    2
            Revoked Certificates:
                Serial Number: 974334424887268612135789888477522013103955028514 (0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA22)
                    Revocation Date: 2026-01-01 00:00:00 +0000 UTC
                Serial Number: 974334424887268612135789888477522013103955028531 (0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA33)
                    Revocation Date: 2026-01-01 00:00:00 +0000 UTC
                Serial Number: 974334424887268612135789888477522013103955028548 (0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA44)
                    Revocation Date: 2026-01-01 00:00:00 +0000 UTC

Note that the serial number `0xAA...AA11` has been removed and the CRL number increased from 1 to 2.