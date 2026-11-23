//go:build localstack

package session

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/thelemail/trust"
	"github.com/thelemail/trust/tlog"
)

func directoryVerifier() (*trust.Verifier, error) {
	root := os.Getenv("THELEMAIL_DIRECTORY_SIGNING_PUBLIC_KEY_ARMORED")
	if root == "" {
		return nil, errors.New("set THELEMAIL_DIRECTORY_SIGNING_PUBLIC_KEY_ARMORED for a local-stack build")
	}
	return trust.NewVerifier(root)
}

func transparencyVerifier() (*tlog.Verifier, error) {
	raw := os.Getenv("THELEMAIL_TLOG_POLICY")
	if raw == "" {
		return nil, nil
	}
	var policy tlog.Policy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		return nil, err
	}
	return tlog.NewVerifier(policy)
}
