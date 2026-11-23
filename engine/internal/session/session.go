package session

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/thelemail/export-tool/transfer"
	"github.com/thelemail/migrator/engine/internal/config"
)

type Session = transfer.Session
type FactorPrompt = func(context.Context, []string, string) (string, string, error)

func Login(ctx context.Context, email, password string, prompt FactorPrompt, passkeyShown func(code string)) (*Session, string, error) {
	cfg := transfer.Config{API: config.API, Web: config.Web, Client: config.ClientType}
	s, err := transfer.LoginInteractive(ctx, cfg, email, password,
		transfer.LoginFactors{Prompt: prompt, Passkey: browserPasskey(email, passkeyShown)}, io.Discard, io.Discard)
	if err != nil {
		return nil, "", err
	}
	var me struct {
		AccountID string `json:"accountId"`
		Email     string `json:"email"`
	}
	err = query(ctx, s, http.MethodGet, "/v1/me", nil, &me)
	if err == nil && (me.AccountID != s.AccountID || me.Email == "") {
		err = errors.New("could not confirm your mailbox identity")
	}
	if err != nil {
		s.Close()
		return nil, "", err
	}
	return s, me.Email, nil
}
