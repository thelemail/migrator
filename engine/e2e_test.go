//go:build e2e && localstack

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	"github.com/google/uuid"

	"github.com/thelemail/export-tool/transfer"
	"github.com/thelemail/migrator/engine/internal/config"
	"github.com/thelemail/migrator/engine/internal/destination"
	"github.com/thelemail/migrator/engine/internal/session"
	"github.com/thelemail/migrator/engine/internal/source"
)

func TestMain(m *testing.M) {
	if api := os.Getenv("MIGRATOR_E2E_API"); api != "" {
		config.API = api
	} else {
		config.API = "http://localhost:8180"
	}
	if auth := os.Getenv("MIGRATOR_E2E_AUTH"); auth != "" {
		config.Auth = auth
	} else {
		config.Auth = "http://localhost:5177"
	}
	if web := os.Getenv("MIGRATOR_E2E_WEB"); web != "" {
		config.Web = web
	} else {
		config.Web = "http://localhost:5173"
	}
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func need(t *testing.T, keys ...string) []string {
	t.Helper()
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		v := os.Getenv(k)
		if v == "" {
			t.Skipf("set %s to run this test against the local stack", k)
		}
		out = append(out, v)
	}
	return out
}

func noFactor(t *testing.T) session.FactorPrompt {
	return func(_ context.Context, methods []string, message string) (string, string, error) {
		t.Fatalf("unexpected second factor %v (%s)", methods, message)
		return "", "", nil
	}
}

func mustSignIn(t *testing.T, email, password string, prompt session.FactorPrompt, passkeyShown ...func(string)) *session.Session {
	t.Helper()
	shown := func(string) {}
	if len(passkeyShown) > 0 {
		shown = passkeyShown[0]
	}
	s, address, err := session.Login(t.Context(), email, password, prompt, shown)
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	t.Cleanup(s.Close)
	if !strings.EqualFold(address, email) {
		t.Fatalf("signed in as %s, want %s", address, email)
	}
	return s
}

func call(t *testing.T, s *session.Session, method, path string, body, out any) int {
	t.Helper()
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, s.BaseURL+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return resp.StatusCode
}

func totp(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		t.Fatalf("TOTP secret: %v", err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

func TestPasswordSignIn(t *testing.T) {
	v := need(t, "MIGRATOR_E2E_EMAIL", "MIGRATOR_E2E_PASSWORD")
	s := mustSignIn(t, v[0], v[1], noFactor(t))
	if !s.ProductKeys.Verified() {
		t.Fatalf("product keys did not verify: %v", s.ProductKeys.Problem)
	}
	var me struct {
		AccountID string `json:"accountId"`
	}
	if code := call(t, s, http.MethodGet, "/v1/me", nil, &me); code != http.StatusOK || me.AccountID != s.AccountID {
		t.Fatalf("/v1/me = %d %s", code, me.AccountID)
	}
	for _, route := range [][2]string{{http.MethodGet, "/v1/auth/sessions"}, {http.MethodGet, "/v1/drafts"}, {http.MethodGet, "/v1/me/signatures"}} {
		if code := call(t, s, route[0], route[1], nil, nil); code != http.StatusUnauthorized {
			t.Errorf("a transfer session reached %s %s: %d", route[0], route[1], code)
		}
	}
	web := webSignIn(t, v[0], v[1])
	var sessions struct {
		Sessions []struct {
			Client string `json:"client"`
		} `json:"sessions"`
	}
	if code := call(t, web, http.MethodGet, "/v1/auth/sessions", nil, &sessions); code != http.StatusOK {
		t.Fatalf("list sessions = %d", code)
	}
	if !slices.ContainsFunc(sessions.Sessions, func(x struct {
		Client string `json:"client"`
	}) bool {
		return x.Client == config.ClientType
	}) {
		t.Fatalf("no %s session in %+v", config.ClientType, sessions.Sessions)
	}
}

func TestWrongPasswordIsReported(t *testing.T) {
	v := need(t, "MIGRATOR_E2E_EMAIL")
	_, _, err := session.Login(t.Context(), v[0], "not the password "+uuid.NewString(), noFactor(t), nil)
	if !errors.Is(err, transfer.ErrWrongPassword) || describe(err).code != "wrong_password" {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthenticatorCodeSignIn(t *testing.T) {
	v := need(t, "MIGRATOR_E2E_TOTP_EMAIL", "MIGRATOR_E2E_TOTP_PASSWORD", "MIGRATOR_E2E_TOTP_SECRET")
	prompts := 0
	mustSignIn(t, v[0], v[1], func(_ context.Context, methods []string, message string) (string, string, error) {
		prompts++
		if prompts == 1 {
			return "totp", "000000", nil
		}
		if message == "" {
			t.Fatal("a declined code was not reported")
		}
		return "totp", totp(t, v[2], time.Now()), nil
	})
	if prompts != 2 {
		t.Fatalf("prompted %d times", prompts)
	}
}

func TestBackupCodeSignIn(t *testing.T) {
	v := need(t, "MIGRATOR_E2E_BACKUP_EMAIL", "MIGRATOR_E2E_BACKUP_PASSWORD", "MIGRATOR_E2E_BACKUP_CODE")
	mustSignIn(t, v[0], v[1], func(_ context.Context, methods []string, _ string) (string, string, error) {
		return "backupCode", v[2], nil
	})
}

type passkeyFixture struct {
	CredentialID string `json:"credentialId"`
	PrivateKey   string `json:"privateKey"`
	RPID         string `json:"rpId"`
	UserHandle   string `json:"userHandle"`
}

func TestPasskeySignInThroughTheBrowser(t *testing.T) {
	v := need(t, "MIGRATOR_E2E_PASSKEY_EMAIL", "MIGRATOR_E2E_PASSKEY_PASSWORD", "MIGRATOR_E2E_PASSKEY_CREDENTIAL")
	var fixture passkeyFixture
	if err := json.Unmarshal([]byte(v[2]), &fixture); err != nil {
		t.Fatalf("MIGRATOR_E2E_PASSKEY_CREDENTIAL: %v", err)
	}
	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			t.Fatalf("passkey fixture: %v", err)
		}
		return b
	}
	alloc, stopAlloc := chromedp.NewExecAllocator(t.Context(), append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Headless)...)
	defer stopAlloc()
	browser, stopBrowser := chromedp.NewContext(alloc)
	defer stopBrowser()
	if _, err := chromedp.Call(browser, webauthn.Enable, webauthn.EnableParams{}); err != nil {
		t.Fatalf("enable WebAuthn: %v", err)
	}
	auth, err := chromedp.Call(browser, webauthn.AddVirtualAuthenticator, webauthn.AddVirtualAuthenticatorParams{Options: &webauthn.VirtualAuthenticatorOptions{
		Protocol: webauthn.AuthenticatorProtocolCtap2, Transport: webauthn.AuthenticatorTransportInternal,
		HasResidentKey: true, HasUserVerification: true, IsUserVerified: true, AutomaticPresenceSimulation: true,
	}})
	if err != nil {
		t.Fatalf("virtual authenticator: %v", err)
	}
	if _, err := chromedp.Call(browser, webauthn.AddCredential, webauthn.AddCredentialParams{AuthenticatorID: auth.AuthenticatorID, Credential: &webauthn.Credential{
		CredentialID: decode(fixture.CredentialID), PrivateKey: decode(fixture.PrivateKey), RpID: fixture.RPID,
		UserHandle: decode(fixture.UserHandle), IsResidentCredential: true,
	}}); err != nil {
		t.Fatalf("add credential: %v", err)
	}
	outcome := ""
	var shownCode string
	session.UseBrowser(func(ctx context.Context, page string) error {
		go func() {
			if err := chromedp.Do(browser, chromedp.Navigate(page)); err != nil {
				t.Errorf("open passkey page: %v", err)
				return
			}
			clicked := false
			for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
				if !clicked {
					text, _ := chromedp.Run(browser, chromedp.Evaluate[string](`document.body.innerText`))
					if shownCode == "" || !strings.Contains(text, shownCode) || !strings.Contains(text, v[0]) {
						continue
					}
					clicked, _ = chromedp.Run(browser, chromedp.Evaluate[bool](`(() => { const b = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Use passkey'); if (!b) return false; b.click(); return true })()`))
					continue
				}
				hash, _ := chromedp.Run(browser, chromedp.Evaluate[string](`location.hash`))
				if strings.HasPrefix(hash, "#done=") {
					outcome = strings.TrimPrefix(hash, "#done=")
					return
				}
			}
			t.Error("the passkey page never handed back to Migrator")
		}()
		return nil
	})
	mustSignIn(t, v[0], v[1], func(_ context.Context, methods []string, message string) (string, string, error) {
		if message != "" {
			t.Fatalf("passkey prompt failed: %s", message)
		}
		return "webauthn", "", nil
	}, func(code string) { shownCode = code })
	time.Sleep(time.Second)
	if outcome != "ok" {
		t.Fatalf("browser outcome %q", outcome)
	}
}

func TestLockoutSaysHowLongToWait(t *testing.T) {
	v := need(t, "MIGRATOR_E2E_LOCKOUT_EMAIL")
	var wait *transfer.WaitError
	for attempt := range 30 {
		_, _, err := session.Login(t.Context(), v[0], fmt.Sprintf("wrong %d %s", attempt, uuid.NewString()), noFactor(t), nil)
		if errors.As(err, &wait) {
			break
		}
		if !errors.Is(err, transfer.ErrWrongPassword) {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	if wait == nil || !errors.Is(wait, transfer.ErrRateLimited) || wait.Wait <= 0 {
		t.Fatalf("no lockout with a wait: %+v", wait)
	}
	if p := describe(wait); p.code != "rate_limited" || !strings.Contains(p.message, "Try again in") {
		t.Fatalf("lockout problem %+v", p)
	}
}

func TestProofIsSolvedAfterFailures(t *testing.T) {
	v := need(t, "MIGRATOR_E2E_PROOF_EMAIL", "MIGRATOR_E2E_PROOF_PASSWORD")
	for attempt := range 3 {
		if _, _, err := session.Login(t.Context(), v[0], fmt.Sprintf("wrong %d", attempt), noFactor(t), nil); !errors.Is(err, transfer.ErrWrongPassword) {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	mustSignIn(t, v[0], v[1], noFactor(t))
}

func webSignIn(t *testing.T, email, password string) *session.Session {
	t.Helper()
	web, err := transfer.LoginInteractive(t.Context(), transfer.Config{API: config.API, Web: config.Web}, email, password, transfer.LoginFactors{Prompt: noFactor(t)}, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("web sign in: %v", err)
	}
	t.Cleanup(web.Close)
	return web
}

func TestRevokedSessionEndsTheTransfer(t *testing.T) {
	v := need(t, "MIGRATOR_E2E_EMAIL", "MIGRATOR_E2E_PASSWORD")
	first := mustSignIn(t, v[0], v[1], noFactor(t))
	second := webSignIn(t, v[0], v[1])
	if code := call(t, second, http.MethodPost, "/v1/auth/sessions/revoke-others", map[string]any{}, nil); code >= 300 {
		t.Fatalf("revoke others = %d", code)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, first.BaseURL+"/v1/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Do(req); !errors.Is(err, transfer.ErrSessionEnded) {
		t.Fatalf("revoked session: err = %v", err)
	}
	if describe(fmt.Errorf("import: %w", transfer.ErrSessionEnded)).code != "session_ended" {
		t.Fatal("ended session is not reported as such")
	}
}

func TestSessionRefreshesDuringALongTransfer(t *testing.T) {
	v := need(t, "MIGRATOR_E2E_EMAIL", "MIGRATOR_E2E_PASSWORD", "MIGRATOR_E2E_ACCESS_TTL")
	ttl, err := time.ParseDuration(v[2])
	if err != nil {
		t.Fatalf("MIGRATOR_E2E_ACCESS_TTL: %v", err)
	}
	s := mustSignIn(t, v[0], v[1], noFactor(t))
	time.Sleep(ttl + 2*time.Second)
	if code := call(t, s, http.MethodGet, "/v1/me", nil, nil); code != http.StatusOK {
		t.Fatalf("after the access token expired: %d", code)
	}
}

type imapFixture struct {
	address string
	user    *imapmemserver.User
}

func startIMAP(t *testing.T) imapFixture {
	t.Helper()
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("old@example.test", "app password")
	mem.AddUser(user)
	web := httptest.NewUnstartedServer(http.NotFoundHandler())
	web.StartTLS()
	t.Cleanup(web.Close)
	pool := x509.NewCertPool()
	pool.AddCert(web.Certificate())
	source.TrustRoots(pool)
	t.Cleanup(func() { source.TrustRoots(nil) })
	server := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:   imap.CapSet{imap.CapIMAP4rev1: {}},
		Logger: log.New(io.Discard, "", 0),
	})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", web.TLS.Clone())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	return imapFixture{address: ln.Addr().String(), user: user}
}

type literal struct{ *strings.Reader }

func (l literal) Size() int64 { return int64(l.Len()) }

func (f imapFixture) mailbox(t *testing.T, name string) {
	t.Helper()
	if err := f.user.Create(name, nil); err != nil {
		t.Fatal(err)
	}
}

func (f imapFixture) add(t *testing.T, mailbox, raw string, at time.Time, flags ...imap.Flag) {
	t.Helper()
	if _, err := f.user.Append(mailbox, literal{strings.NewReader(raw)}, &imap.AppendOptions{Flags: flags, Time: at}); err != nil {
		t.Fatal(err)
	}
}

type listed struct {
	ID        string     `json:"id"`
	Direction string     `json:"direction"`
	Mailbox   string     `json:"mailboxState"`
	FolderID  string     `json:"folderId"`
	StoredAt  time.Time  `json:"storedAt"`
	ReadAt    *time.Time `json:"readAt"`
	StarredAt *time.Time `json:"starredAt"`
}

func listAt(t *testing.T, s *session.Session, query url.Values, at time.Time) []listed {
	t.Helper()
	query.Set("limit", "200")
	var page struct {
		Items []listed `json:"items"`
	}
	if code := call(t, s, http.MethodGet, "/v1/messages?"+query.Encode(), nil, &page); code != http.StatusOK {
		t.Fatalf("list %v = %d", query, code)
	}
	var out []listed
	for _, m := range page.Items {
		if m.StoredAt.Equal(at) {
			out = append(out, m)
		}
	}
	return out
}

func TestAcceptanceImportKeepsPlacementAcrossAnInterruption(t *testing.T) {
	v := need(t, "MIGRATOR_E2E_EMAIL", "MIGRATOR_E2E_PASSWORD")
	s := mustSignIn(t, v[0], v[1], noFactor(t))
	run := make([]byte, 4)
	_, _ = rand.Read(run)
	tag := hex.EncodeToString(run)
	base := time.Date(2003, 2, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(binary.BigEndian.Uint32(run)%100000) * time.Minute)
	inboxAt, sentAt, starAt := base, base.Add(time.Second), base.Add(2*time.Second)
	f := startIMAP(t)
	clients, empty := "Clients "+tag, "Empty "+tag
	for _, name := range []string{"INBOX", "Sent", clients, clients + "/Acme", empty} {
		f.mailbox(t, name)
	}
	shared := fmt.Sprintf("<acceptance-%s@example.test>", tag)
	f.add(t, "INBOX", "Message-ID: "+shared+"\r\nSubject: unread inbox\r\n\r\nbody\r\n", inboxAt)
	f.add(t, "Sent", "Message-ID: "+shared+"\r\nSubject: sent copy\r\n\r\nbody\r\n", sentAt, imap.FlagSeen)
	f.add(t, clients+"/Acme", fmt.Sprintf("Message-ID: <star-%s@example.test>\r\nSubject: starred\r\n\r\nbody\r\n", tag), starAt, imap.FlagSeen, imap.FlagFlagged)
	src := transferSource{Kind: "imap", Server: f.address, Username: "old@example.test", Password: "app password"}

	interrupted, stop := context.WithCancel(t.Context())
	err := runTransfer(interrupted, s, src, func(message string) {
		if strings.Contains(message, "1 copied") {
			stop()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted transfer: %v", err)
	}
	var summary string
	if err := runTransfer(t.Context(), s, src, func(m string) { summary = m }); err != nil {
		t.Fatalf("resumed transfer: %v", err)
	}
	if !strings.Contains(summary, "Import complete") {
		t.Fatalf("summary %q", summary)
	}

	inbox := listAt(t, s, url.Values{"mailbox": {"inbox"}, "direction": {"received"}}, inboxAt)
	if len(inbox) != 1 || inbox[0].ReadAt != nil {
		t.Fatalf("inbox = %+v", inbox)
	}
	sent := listAt(t, s, url.Values{"mailbox": {"inbox"}, "direction": {"sent"}}, sentAt)
	if len(sent) != 1 || sent[0].ReadAt == nil {
		t.Fatalf("sent = %+v", sent)
	}
	key, err := s.MigrationKey()
	if err != nil {
		t.Fatal(err)
	}
	folders := destination.CollectionResolver(t.Context(), s, key, destination.KindFolder)
	acme, err := folders([]string{clients, "Acme"}, "")
	if err != nil {
		t.Fatal(err)
	}
	emptyID, err := folders([]string{empty}, "")
	if err != nil || emptyID == "" {
		t.Fatalf("empty folder was not created: %v", err)
	}
	starred := listAt(t, s, url.Values{"folderId": {acme}}, starAt)
	if len(starred) != 1 || starred[0].StarredAt == nil || starred[0].FolderID != acme {
		t.Fatalf("starred folder message = %+v", starred)
	}

	if err := runTransfer(t.Context(), s, src, func(m string) { summary = m }); err != nil || !strings.Contains(summary, "0 copied") {
		t.Fatalf("third run: %v %q", err, summary)
	}
	if n := len(listAt(t, s, url.Values{"mailbox": {"inbox"}, "direction": {"received"}}, inboxAt)); n != 1 {
		t.Fatalf("inbox count after a rerun = %d", n)
	}

	raw := []byte(fmt.Sprintf("Message-ID: <foreign-%s@example.test>\r\nSubject: foreign\r\n\r\nbody\r\n", tag))
	foreign := &destination.Placement{Mailbox: "folder", FolderID: uuid.NewString(), Read: true, SourceKey: source.Identity(key, "foreign", tag)}
	if _, err := destination.Import(t.Context(), s, raw, foreign, base); !errors.Is(err, destination.ErrFolderRejected) {
		t.Fatalf("foreign folder: %v", err)
	}
}
