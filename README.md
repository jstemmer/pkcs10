# No longer maintained

This project is no longer being maintained. Go 1.3 added support for PKCS#10
certificate signing requests to the [crypto/x509](https://golang.org/pkg/crypto/x509/)
package.

# pkcs10

Package pkcs10 parses and creates PKCS#10 certificate signing requests, as
specified in RFC 2986.

[![Build Status](https://travis-ci.org/jstemmer/pkcs10.png?branch=master)](https://travis-ci.org/jstemmer/pkcs10)

## Documentation

http://godoc.org/github.com/jstemmer/pkcs10

## License

See LICENSE.

Some unexported functions and variables in the official `crypto/x509` package
from the Go source have been used, all contained in the `x509.go` file, under
the license in LICENSE-GO.
