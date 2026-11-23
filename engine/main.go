package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/thelemail/export-tool/transfer"
	"github.com/thelemail/migrator/engine/internal/config"
	"github.com/thelemail/migrator/engine/internal/session"
	"github.com/thelemail/migrator/engine/internal/source"
)

type command struct {
	Type, Email, Password, Method, Code string
	Source                              transferSource
}

type importState struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type event struct {
	Type    string       `json:"type"`
	Code    string       `json:"code,omitempty"`
	Message string       `json:"message,omitempty"`
	Detail  string       `json:"detail,omitempty"`
	Methods []string     `json:"methods,omitempty"`
	Confirm string       `json:"confirm,omitempty"`
	Email   string       `json:"email,omitempty"`
	Version string       `json:"version,omitempty"`
	Import  *importState `json:"import,omitempty"`
	Resume  *resumable   `json:"resume,omitempty"`
	Check   *sourceCheck `json:"check,omitempty"`
}

type sourceCheck struct {
	Address  string `json:"address"`
	Security string `json:"security"`
	Folders  int    `json:"folders"`
	Messages int    `json:"messages"`
}

type mailbox struct {
	email    string
	imports  importState
	resume   *resumable
	check    func(context.Context, transferSource) (sourceCheck, error)
	transfer func(context.Context, transferSource, func(string)) error
	verify   func(context.Context) importState
	close    func()
}

type loginFunc func(context.Context, string, string, session.FactorPrompt, func(string)) (*mailbox, error)

type update struct {
	event
	reply chan<- command
	mail  *mailbox
	done  bool
	ended bool
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("engine ")
	if err := serve(os.Stdin, os.Stdout, openMailbox); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func importsOf(s *session.Session) importState {
	if s.ProductKeys.Verified() {
		return importState{Allowed: true}
	}
	log.Printf("account keys did not verify: %s", logLine("keys_unverified", s.ProductKeys.Problem))
	return importState{Reason: describe(session.ErrKeysUnverified).message}
}

func openMailbox(ctx context.Context, email, password string, prompt session.FactorPrompt, passkeyShown func(string)) (*mailbox, error) {
	s, address, err := session.Login(ctx, email, password, prompt, passkeyShown)
	if err != nil {
		return nil, err
	}
	last, err := lastTransfer(s.AccountID)
	if err != nil {
		log.Print("could not read the last transfer")
	}
	return &mailbox{
		email: address, imports: importsOf(s), resume: last, close: s.Close,
		check: checkSource,
		transfer: func(ctx context.Context, src transferSource, progress func(string)) error {
			return runTransfer(ctx, s, src, progress)
		},
		verify: func(ctx context.Context) importState {
			s.VerifyProductKeys(ctx)
			return importsOf(s)
		},
	}, nil
}

func readCommands(ctx context.Context, input io.Reader, commands chan<- command) {
	defer close(commands)
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		var c command
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&c); err != nil || decoder.Decode(new(any)) != io.EOF {
			c = command{}
		}
		select {
		case commands <- c:
		case <-ctx.Done():
			return
		}
	}
}

func serve(input io.Reader, output io.Writer, login loginFunc) error {
	ctx, shutdown := context.WithCancel(context.Background())
	defer shutdown()
	commands := make(chan command)
	go readCommands(ctx, input, commands)
	changes := make(chan update)
	send := json.NewEncoder(output).Encode
	var mail *mailbox
	var cancel context.CancelFunc
	var reply chan<- command
	defer func() {
		shutdown()
		if cancel != nil {
			cancel()
			for change := range changes {
				if change.done {
					if change.mail != nil {
						change.mail.close()
					}
					break
				}
			}
		}
		if mail != nil {
			mail.close()
		}
	}()
	if err := send(event{Type: "ready", Version: config.Version}); err != nil {
		return err
	}
	start := func(job func(context.Context)) {
		jobCtx, stop := context.WithCancel(ctx)
		cancel = stop
		go job(jobCtx)
	}
	for {
		select {
		case c, ok := <-commands:
			if !ok {
				return nil
			}
			switch {
			case c.Type == "cancel":
				if cancel != nil {
					cancel()
				} else if err := send(event{Type: "stopped"}); err != nil {
					return err
				}
			case c.Type == "factor" && reply != nil:
				reply <- command{Method: c.Method, Code: c.Code}
				reply = nil
			case cancel != nil:
				if err := send(event{Type: "error", Code: "busy", Message: "Finish the current step first."}); err != nil {
					return err
				}
			case c.Type == "login" && mail == nil && strings.TrimSpace(c.Email) != "" && c.Password != "":
				start(func(ctx context.Context) { signIn(ctx, login, strings.TrimSpace(c.Email), c.Password, changes) })
			case c.Type == "transfer" && mail != nil:
				m := mail
				start(func(ctx context.Context) { transferMail(ctx, m, c.Source, changes) })
			case c.Type == "check_source" && mail != nil:
				m := mail
				start(func(ctx context.Context) { checkMailbox(ctx, m, c.Source, changes) })
			case c.Type == "verify_keys" && mail != nil:
				m := mail
				start(func(ctx context.Context) { verifyKeys(ctx, m, changes) })
			case c.Type == "logout" && mail != nil:
				mail.close()
				mail = nil
				if err := send(event{Type: "signed_out"}); err != nil {
					return err
				}
			default:
				if err := send(event{Type: "error", Code: "signed_out", Message: "Sign in to Thelemail with your email address and password."}); err != nil {
					return err
				}
			}
		case change := <-changes:
			reply = change.reply
			if change.done {
				cancel()
				cancel = nil
				if change.mail != nil {
					mail = change.mail
				}
				if change.ended && mail != nil {
					mail.close()
					mail = nil
				}
			}
			if err := send(change.event); err != nil {
				return err
			}
		}
	}
}

func signIn(ctx context.Context, login loginFunc, email, password string, changes chan<- update) {
	prompt := func(ctx context.Context, methods []string, message string) (string, string, error) {
		replies := make(chan command, 1)
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case changes <- update{event: event{Type: "challenge", Methods: methods, Message: message}, reply: replies}:
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case c := <-replies:
			return c.Method, c.Code, nil
		}
	}
	shown := func(code string) {
		select {
		case <-ctx.Done():
		case changes <- update{event: event{Type: "passkey", Confirm: code}}:
		}
	}
	mail, err := login(ctx, email, password, prompt, shown)
	if ctx.Err() != nil && mail != nil {
		mail.close()
		mail = nil
	}
	out := result(ctx, err, "signed_in", "")
	if mail != nil {
		out.Email = mail.email
		imports := mail.imports
		out.Import = &imports
		out.Resume = mail.resume
	}
	changes <- update{event: out, mail: mail, done: true}
}

func transferMail(ctx context.Context, mail *mailbox, src transferSource, changes chan<- update) {
	last := ""
	err := mail.transfer(ctx, src, func(message string) {
		last = message
		select {
		case <-ctx.Done():
		case changes <- update{event: event{Type: "progress", Message: message}}:
		}
	})
	out := result(ctx, err, "finished", last)
	ended := ctx.Err() == nil && errors.Is(err, transfer.ErrSessionEnded)
	if ended {
		out.Type = "signed_out"
	}
	changes <- update{event: out, done: true, ended: ended}
}

func checkMailbox(ctx context.Context, mail *mailbox, src transferSource, changes chan<- update) {
	checked, err := mail.check(ctx, src)
	out := result(ctx, err, "source_checked", "")
	if err == nil && ctx.Err() == nil {
		out.Check = &checked
	}
	changes <- update{event: out, done: true}
}

func checkSource(ctx context.Context, src transferSource) (sourceCheck, error) {
	if src.Kind != "imap" {
		return sourceCheck{}, errors.New("only IMAP mailboxes need a connection check")
	}
	if err := src.validate(); err != nil {
		return sourceCheck{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	summary, err := source.Check(ctx, src.account())
	if err != nil {
		return sourceCheck{}, err
	}
	security := source.SecurityTLS
	if summary.StartTLS {
		security = source.SecurityStartTLS
	}
	return sourceCheck{Address: summary.Address, Security: security, Folders: summary.Folders, Messages: summary.Messages}, nil
}

func verifyKeys(ctx context.Context, mail *mailbox, changes chan<- update) {
	imports := mail.verify(ctx)
	mail.imports = imports
	out := event{Type: "keys_checked", Import: &imports}
	if ctx.Err() != nil {
		out = event{Type: "stopped", Message: "Cancelled."}
	}
	changes <- update{event: out, done: true}
}

func result(ctx context.Context, err error, success, message string) event {
	switch {
	case ctx.Err() != nil:
		return event{Type: "stopped", Message: "Cancelled."}
	case err != nil:
		p := describe(err)
		log.Print(logLine(p.code, err))
		return event{Type: "error", Code: p.code, Message: p.message, Detail: detail(err)}
	default:
		return event{Type: success, Message: message}
	}
}
