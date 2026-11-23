//go:build e2e

package source

import "crypto/x509"

func TrustRoots(pool *x509.CertPool) { trustedRoots = pool }
