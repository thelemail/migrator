package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/thelemail/export-tool/transfer"
	"github.com/thelemail/migrator/engine/internal/config"
)

var ErrPasskeyCancelled = errors.New("passkey verification was cancelled. Try again or choose another method")

const (
	passkeyPath       = "/migrator/passkey"
	passkeyResultPath = "/migrator/passkey/result"
	maxCredentialSize = 16 << 10
	passkeyWait       = 3 * time.Minute
)

var opener = openBrowser

type passkeyPage struct {
	auth, account string
	shown         func(code string)
}

func browserPasskey(account string, shown func(string)) func(context.Context, transfer.PasskeyRequest) (json.RawMessage, error) {
	return func(ctx context.Context, req transfer.PasskeyRequest) (json.RawMessage, error) {
		return requestPasskey(ctx, req, passkeyPage{auth: config.Auth, account: account, shown: shown}, opener)
	}
}

func PasskeyCode(state string) string {
	sum := sha256.Sum256([]byte("thelemail-migrator-passkey:" + state))
	code := base32.StdEncoding.EncodeToString(sum[:5])
	return code[:4] + "-" + code[4:]
}

func openBrowser(ctx context.Context, uri string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "/usr/bin/open", uri)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", uri)
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", uri)
	}
	return cmd.Run()
}

func requestPasskey(ctx context.Context, req transfer.PasskeyRequest, page passkeyPage, open func(context.Context, string) error) (json.RawMessage, error) {
	auth := page.auth
	var cancel context.CancelFunc
	if req.Expires.IsZero() {
		ctx, cancel = context.WithTimeout(ctx, passkeyWait)
	} else {
		ctx, cancel = context.WithDeadline(ctx, req.Expires)
	}
	defer cancel()
	if len(req.Options) == 0 || req.Options[0] != '{' {
		return nil, errors.New("the server did not send passkey options")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("could not open the local passkey connection")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	state := base64.RawURLEncoding.EncodeToString(secret)
	bridge := &passkeyBridge{host: listener.Addr().String(), auth: auth, state: state, result: make(chan json.RawMessage, 1)}
	server := &http.Server{Handler: bridge, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10}
	defer func() {
		drain, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = server.Shutdown(drain)
	}()
	failed := make(chan error, 1)
	go func() { failed <- server.Serve(listener) }()
	target, err := url.Parse(auth + passkeyPath)
	if err != nil {
		return nil, err
	}
	target.Fragment = url.Values{
		"port":    {strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)},
		"state":   {state},
		"options": {base64.RawURLEncoding.EncodeToString(req.Options)},
		"account": {page.account},
	}.Encode()
	if page.shown != nil {
		page.shown(PasskeyCode(state))
	}
	if err := open(ctx, target.String()); err != nil {
		return nil, errors.New("could not open your browser. Try again or choose another verification method")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-failed:
		return nil, fmt.Errorf("the local passkey connection closed. Try again (%w)", err)
	case credential := <-bridge.result:
		if credential == nil {
			return nil, ErrPasskeyCancelled
		}
		return credential, nil
	}
}

type passkeyBridge struct {
	host, auth, state string
	result            chan json.RawMessage
	mu                sync.Mutex
	used              bool
}

func (p *passkeyBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	if r.Host != p.host || r.URL.Path != passkeyResultPath || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(p.state)) != 1 {
		p.finish(w, r, "failed")
		return
	}
	var credential json.RawMessage
	if q.Get("cancel") == "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.Get("credential"))
		if err != nil || len(raw) == 0 || len(raw) > maxCredentialSize || !json.Valid(raw) || raw[0] != '{' {
			p.finish(w, r, "failed")
			return
		}
		credential = raw
	}
	p.mu.Lock()
	used := p.used
	p.used = true
	p.mu.Unlock()
	if used {
		p.finish(w, r, "failed")
		return
	}
	p.result <- credential
	if credential == nil {
		p.finish(w, r, "cancelled")
		return
	}
	p.finish(w, r, "ok")
}

func (p *passkeyBridge) finish(w http.ResponseWriter, r *http.Request, outcome string) {
	http.Redirect(w, r, p.auth+passkeyPath+"#done="+outcome, http.StatusSeeOther)
}
