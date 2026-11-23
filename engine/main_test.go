package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thelemail/export-tool/transfer"
	"github.com/thelemail/migrator/engine/internal/backup"
	"github.com/thelemail/migrator/engine/internal/destination"
	"github.com/thelemail/migrator/engine/internal/session"
	"github.com/thelemail/migrator/engine/internal/source"
)

func TestAuthenticatedWorkflow(t *testing.T) {
	in, commands := io.Pipe()
	events, out := io.Pipe()
	done := make(chan error, 1)
	closed := make(chan struct{})
	login := func(ctx context.Context, email, password string, prompt session.FactorPrompt, _ func(string)) (*mailbox, error) {
		if email != "me@example.test" || password != "fixture" {
			return nil, errors.New("invalid login")
		}
		method, code, err := prompt(ctx, []string{"totp", "webauthn"}, "")
		if err != nil {
			return nil, err
		}
		if method != "totp" || code != "123456" {
			return nil, errors.New("invalid factor")
		}
		verified := false
		return &mailbox{email: email, imports: importState{Reason: "keys"}, resume: &resumable{Kind: "imap", Server: "imap.example.test"}, close: func() { close(closed) }, verify: func(context.Context) importState {
			verified = true
			return importState{Allowed: verified}
		}, check: func(_ context.Context, src transferSource) (sourceCheck, error) {
			if src.Server != "imap.example.test" || src.Port != "993" || src.Security != "tls" {
				return sourceCheck{}, &source.SignInError{Host: "imap.fastmail.com", Err: errors.New("imap: NO Incorrect username, password or access token.")}
			}
			return sourceCheck{Address: "imap.example.test:993", Security: "tls", Folders: 3, Messages: 42}, nil
		}, transfer: func(ctx context.Context, src transferSource, progress func(string)) error {
			switch src.Kind {
			case "files":
				progress("Import complete")
				return nil
			case "export":
				progress("Exporting")
				<-ctx.Done()
				return ctx.Err()
			case "imap":
				return fmt.Errorf("import: %w", transfer.ErrSessionEnded)
			default:
				return errors.New("unknown source")
			}
		}}, nil
	}
	go func() { done <- serve(in, out, login); _ = out.Close() }()
	write := json.NewEncoder(commands).Encode
	read := json.NewDecoder(events)
	expect := func(kind string) event {
		t.Helper()
		var e event
		if err := read.Decode(&e); err != nil || e.Type != kind {
			t.Fatalf("got %+v (%v), want %s", e, err, kind)
		}
		return e
	}
	request := func(c command) {
		t.Helper()
		if err := write(c); err != nil {
			t.Fatal(err)
		}
	}
	if expect("ready").Version == "" {
		t.Fatal("engine did not report its version")
	}
	request(command{Type: "transfer", Source: transferSource{Kind: "files"}})
	expect("error")
	request(command{Type: "login", Email: "me@example.test", Password: "wrong"})
	if e := expect("error"); e.Code != "error" || e.Detail != "invalid login" {
		t.Fatalf("error event %+v", e)
	}
	request(command{Type: "login", Email: "me@example.test", Password: "fixture"})
	if !slices.Equal(expect("challenge").Methods, []string{"totp", "webauthn"}) {
		t.Fatal("missing challenge choices")
	}
	request(command{Type: "cancel"})
	expect("stopped")
	request(command{Type: "login", Email: "me@example.test", Password: "fixture"})
	expect("challenge")
	request(command{Type: "factor", Method: "totp", Code: "123456"})
	signed := expect("signed_in")
	if signed.Email != "me@example.test" || signed.Import == nil || signed.Import.Allowed || signed.Resume == nil || signed.Resume.Server != "imap.example.test" {
		t.Fatalf("signed in %+v", signed)
	}
	request(command{Type: "verify_keys"})
	if e := expect("keys_checked"); e.Import == nil || !e.Import.Allowed {
		t.Fatalf("keys %+v", e)
	}
	request(command{Type: "check_source", Source: transferSource{Kind: "imap", Server: "imap.example.test", Port: "993", Security: "tls", Username: "me", Password: "app"}})
	if e := expect("source_checked"); e.Check == nil || e.Check.Folders != 3 || e.Check.Messages != 42 || e.Check.Security != "tls" {
		t.Fatalf("source check %+v", e)
	}
	request(command{Type: "check_source", Source: transferSource{Kind: "imap", Server: "imap.fastmail.com", Port: "993", Username: "me", Password: "normal"}})
	if e := expect("error"); e.Code != "source_sign_in" || !strings.Contains(e.Message, "Fastmail needs an app password") || !strings.Contains(e.Detail, "Incorrect username") {
		t.Fatalf("source check failure %+v", e)
	}
	request(command{Type: "transfer", Source: transferSource{Kind: "export"}})
	expect("progress")
	request(command{Type: "cancel"})
	expect("stopped")
	request(command{Type: "transfer", Source: transferSource{Kind: "files"}})
	expect("progress")
	if expect("finished").Message != "Import complete" {
		t.Fatal("missing result")
	}
	request(command{Type: "transfer", Source: transferSource{Kind: "imap"}})
	if e := expect("signed_out"); e.Code != "session_ended" || e.Message == "" {
		t.Fatalf("ended session %+v", e)
	}
	<-closed
	request(command{Type: "transfer", Source: transferSource{Kind: "files"}})
	expect("error")
	_ = commands.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLogoutClosesTheMailbox(t *testing.T) {
	in, commands := io.Pipe()
	events, out := io.Pipe()
	closed := make(chan struct{})
	login := func(context.Context, string, string, session.FactorPrompt, func(string)) (*mailbox, error) {
		return &mailbox{email: "me@example.test", imports: importState{Allowed: true}, close: func() { close(closed) }}, nil
	}
	done := make(chan error, 1)
	go func() { done <- serve(in, out, login); _ = out.Close() }()
	write := json.NewEncoder(commands).Encode
	read := json.NewDecoder(events)
	next := func() event {
		var e event
		if err := read.Decode(&e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	next()
	_ = write(command{Type: "login", Email: "me@example.test", Password: "fixture"})
	if e := next(); e.Type != "signed_in" {
		t.Fatalf("%+v", e)
	}
	_ = write(command{Type: "logout"})
	if e := next(); e.Type != "signed_out" || e.Code != "" {
		t.Fatalf("%+v", e)
	}
	<-closed
	_ = commands.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProblemsReadPlainly(t *testing.T) {
	cases := map[error]string{
		fmt.Errorf("x: %w", transfer.ErrWrongPassword):                                 "wrong_password",
		&transfer.WaitError{Err: transfer.ErrRateLimited, Wait: 15 * time.Minute}:      "rate_limited",
		transfer.ErrUpgradeRequired:                                                    "upgrade_required",
		fmt.Errorf("y: %w", transfer.ErrSessionEnded):                                  "session_ended",
		destination.StatusError(http.StatusInsufficientStorage):                        "quota",
		fmt.Errorf("z: %w", destination.ErrFolderRejected):                             "folder_rejected",
		fmt.Errorf("verify: %w", session.ErrKeysUnverified):                            "keys_unverified",
		errors.New("unexpected"):                                                       "error",
		&source.SignInError{Host: "imap.example.test", Err: errors.New("NO")}:          "source_sign_in",
		&source.ConnectError{Address: "imap.example.test:993", Err: errors.New("EOF")}: "source_connect",
		&backup.Incomplete{Pending: 2}:                                                 "export_incomplete",
		&backup.Incomplete{Lost: 5}:                                                    "export_unreadable",
		&backup.Incomplete{KeyProblems: true}:                                          "export_keys",
	}
	for err, code := range cases {
		p := describe(err)
		if p.code != code || p.message == "" || strings.Contains(p.message, "—") {
			t.Errorf("%v: %+v, want %s", err, p, code)
		}
	}
	if got := describe(&backup.Incomplete{Lost: 5}).message; !strings.Contains(got, "5 messages couldn't be decrypted") {
		t.Errorf("export warning %q", got)
	}
	for host, want := range map[string]string{"imap.fastmail.com": "Fastmail", "imap.gmail.com": "Gmail", "imap.mail.me.com": "iCloud", "outlook.office365.com": "MBOX", "mail.example.test": "app password"} {
		if got := passwordTip(host); !strings.Contains(got, want) {
			t.Errorf("tip for %s = %q", host, got)
		}
	}
	if got := describe(&transfer.WaitError{Err: transfer.ErrRateLimited, Wait: 15 * time.Minute}).message; !strings.Contains(got, "15 minutes") {
		t.Errorf("rate limit message %q", got)
	}
}

func TestLogLinesCarryNoErrorText(t *testing.T) {
	private := errors.New("imap.example.test said no to ada@example.test")
	if got := logLine("source_sign_in", fmt.Errorf("sign in: %w", private)); got != "source_sign_in" {
		t.Fatalf("logLine = %q", got)
	}
	if got := logLine("quota", fmt.Errorf("upload ada@example.test: %w", destination.StatusError(http.StatusInsufficientStorage))); got != "quota (HTTP 507)" {
		t.Fatalf("logLine = %q", got)
	}
}
