package source

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

type fixtureMailbox struct {
	address string
	user    *imapmemserver.User
}

func startFixture(t *testing.T) fixtureMailbox {
	t.Helper()
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("owner@example.test", "app password")
	mem.AddUser(user)
	options := &imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:   imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapSpecialUse: {}},
		Logger: log.New(io.Discard, "", 0),
	}
	web := httptest.NewUnstartedServer(http.NotFoundHandler())
	web.StartTLS()
	t.Cleanup(web.Close)
	options.TLSConfig = web.TLS.Clone()
	pool := x509.NewCertPool()
	pool.AddCert(web.Certificate())
	trustedRoots = pool
	t.Cleanup(func() { trustedRoots = nil })
	server := imapserver.New(options)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	return fixtureMailbox{address: ln.Addr().String(), user: user}
}

func (f fixtureMailbox) add(t *testing.T, mailbox string, n int, flags ...imap.Flag) {
	t.Helper()
	if err := f.user.Create(mailbox, nil); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		raw := fmt.Sprintf("Message-ID: <%s-%d@example.test>\r\nSubject: %s %d\r\n\r\nbody\r\n", strings.ToLower(mailbox), i, mailbox, i)
		if _, err := f.user.Append(mailbox, literal(raw), &imap.AppendOptions{Flags: flags, Time: time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)}); err != nil {
			t.Fatal(err)
		}
	}
}

type literalReader struct{ *strings.Reader }

func (l literalReader) Size() int64 { return int64(l.Len()) }

func literal(s string) imap.LiteralReader { return literalReader{strings.NewReader(s)} }

func TestIMAPSignsInWithPlainOverStartTLS(t *testing.T) {
	f := startFixture(t)
	f.add(t, "INBOX", 1)
	account := IMAPAccount{Server: f.address, Username: "owner@example.test", Password: "app password"}
	_, closeClient, _, err := connectWith(t.Context(), account, true)
	if err != nil {
		t.Fatalf("STARTTLS sign-in: %v", err)
	}
	closeClient()
	if _, _, _, err := connectWith(t.Context(), account, false); err == nil {
		t.Fatal("signed in without TLS to a server that requires it")
	}
	if _, _, _, err := connectWith(t.Context(), IMAPAccount{Server: f.address, Username: "owner@example.test", Password: "wrong"}, true); !errors.Is(err, ErrSourceSignIn) {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestIMAPSkipsVirtualMailboxesAndKnownMessages(t *testing.T) {
	f := startFixture(t)
	f.add(t, "INBOX", 3)
	f.add(t, "Archive", 1, imap.FlagSeen)
	account := IMAPAccount{Server: f.address, Username: "owner@example.test", Password: "app password"}
	client, closeClient, address, err := connectWith(t.Context(), account, true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	key := []byte("local key")
	inboxKey := func(uid int) []byte {
		return Identity(key, "message", strings.ToLower(address), account.Username, "INBOX", "1", fmt.Sprint(uid))
	}
	var asked int
	known := func(keys [][]byte) (map[string]bool, error) {
		asked += len(keys)
		return map[string]bool{string(inboxKey(2)): true}, nil
	}
	var visited []string
	previous, err := copyMailbox(t.Context(), client, account, "dest", t.TempDir(), address, key, func(folder Folder) (IMAPVisit, error) {
		return func(name string, _ []byte, info MessageInfo, readErr error) error {
			visited = append(visited, name)
			return readErr
		}, nil
	}, known, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(visited)
	want := []string{"Archive UID 1", "INBOX UID 1", "INBOX UID 3"}
	if previous != 1 || !slices.Equal(visited, want) || asked != 4 {
		t.Fatalf("previous %d asked %d visited %v", previous, asked, visited)
	}
}
