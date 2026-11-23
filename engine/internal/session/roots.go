//go:build !localstack

package session

import (
	"github.com/thelemail/trust"
	"github.com/thelemail/trust/tlog"
)

func directoryVerifier() (*trust.Verifier, error) { return trust.Production, nil }

func transparencyVerifier() (*tlog.Verifier, error) { return tlog.Production, nil }
