package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/thelemail/trust/tlog"
)

var ErrKeysUnverified = errors.New("the destination account keys could not be verified")

type directoryEntry struct {
	PublicKeyArmored string `json:"publicKeyArmored"`
	Statement        []byte `json:"directoryStatementRaw"`
	Signature        string `json:"directorySignature"`
	Proof            string `json:"tlogProof"`
}

func VerifyImport(ctx context.Context, s *Session) error {
	if !s.ProductKeys.Verified() {
		return fmt.Errorf("%w: %w", ErrKeysUnverified, s.ProductKeys.Problem)
	}
	var account struct {
		AccountID string `json:"accountId"`
		Email     string `json:"email"`
	}
	if err := query(ctx, s, http.MethodGet, "/v1/me", nil, &account); err != nil {
		return err
	}
	address := strings.ToLower(strings.TrimSpace(account.Email))
	if account.AccountID != s.AccountID || address == "" {
		return errors.New("invalid destination mailbox identity")
	}
	body, err := json.Marshal(map[string]string{"email": address})
	if err != nil {
		return err
	}
	var entry directoryEntry
	if err := query(ctx, s, http.MethodPost, "/v1/accounts/lookup", body, &entry); err != nil {
		return err
	}
	return verifyEntry(entry, address, s.AccountID, s.Fingerprint)
}

func query(ctx context.Context, s *Session, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, s.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.Do(req)
	if err != nil {
		return fmt.Errorf("verify destination account: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return &StatusError{Status: resp.StatusCode, During: "verify destination account"}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(out)
}

func verifyEntry(entry directoryEntry, email, account string, fingerprint []byte) error {
	directory, err := directoryVerifier()
	if err != nil {
		return err
	}
	result, err := directory.VerifyDirectory(entry.Statement, entry.Signature, entry.PublicKeyArmored, email)
	if err != nil {
		return fmt.Errorf("verify signed mailbox key: %w", err)
	}
	if result.Statement.AccountID != account || result.Statement.KeyFingerprint != hex.EncodeToString(fingerprint) {
		return errors.New("the verified mailbox key does not match the unlocked account")
	}
	transparency, err := transparencyVerifier()
	if err != nil || transparency == nil {
		return err
	}
	_, err = transparency.Verify(tlog.Request{Address: email, Statement: result.Canonical, TlogProof: entry.Proof})
	if err != nil {
		return fmt.Errorf("verify mailbox key transparency proof: %w", err)
	}
	return nil
}

type StatusError struct {
	Status int
	During string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s: HTTP %d (%s)", e.During, e.Status, http.StatusText(e.Status))
}
