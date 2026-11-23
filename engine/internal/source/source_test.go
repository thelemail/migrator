package source

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

func TestFileAndMboxDirectory(t *testing.T) {
	dir := t.TempDir()
	payload := "From example date\nSubject: First\n\n>From here\n>>From someone\n\nFrom example date\nSubject: Second\n\n" + strings.Repeat("x", 128<<10) + "\n\n"
	for name, text := range map[string]string{"inbox.mbox": payload, "loose.EML": "Subject: Loose\r\n\r\nHi", "settings.json": "{}"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var messages []string
	err := Files(t.Context(), dir, func(_ string, raw []byte, err error) error {
		messages = append(messages, string(raw))
		return err
	})
	if err != nil || len(messages) != 3 {
		t.Fatalf("read %d messages: %v", len(messages), err)
	}
	if messages[0] != "Subject: First\n\nFrom here\n>From someone\n" ||
		!strings.Contains(messages[1], strings.Repeat("x", 128<<10)) || messages[2] != "Subject: Loose\r\n\r\nHi" {
		t.Fatal("message contents changed")
	}
}

func TestFileSkipsOversizedMessageAndReadsNext(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "a.eml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxMessageBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.eml"), []byte("Subject: OK\n\nBody"), 0600); err != nil {
		t.Fatal(err)
	}
	var statuses []bool
	err = Files(t.Context(), dir, func(_ string, _ []byte, err error) error {
		statuses = append(statuses, errors.Is(err, ErrTooLarge))
		return nil
	})
	if err != nil || !slices.Equal(statuses, []bool{true, false}) {
		t.Fatalf("statuses %v: %v", statuses, err)
	}
}

func TestFileStopsOnTransferError(t *testing.T) {
	stop := errors.New("stop")
	count := 0
	err := readMbox(t.Context(), strings.NewReader("From a\nSubject: A\n\none\n\nFrom b\nSubject: B\n\ntwo"), "test", func(_ string, _ []byte, _ error) error { count++; return stop })
	if !errors.Is(err, stop) || count != 1 {
		t.Fatalf("got %d visits and %v", count, err)
	}
}

func TestIMAPResumeAndLateArrival(t *testing.T) {
	dir := t.TempDir()
	mail := []byte("Subject: Imported\r\n\r\nx\r\n")
	transfer := func(total, validity int, interrupt bool) ([]string, int, error) {
		app, server := net.Pipe()
		_ = app.SetDeadline(time.Now().Add(4 * time.Second))
		_ = server.SetDeadline(time.Now().Add(4 * time.Second))
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() { _ = server.Close() }()
			_, _ = fmt.Fprint(server, "* PREAUTH [CAPABILITY IMAP4rev1] Test server\r\n")
			scanner := bufio.NewScanner(server)
			for scanner.Scan() {
				line := scanner.Text()
				fields := strings.Fields(line)
				if len(fields) < 2 {
					return
				}
				tag := fields[0]
				switch {
				case strings.HasPrefix(line, tag+" EXAMINE "):
					_, _ = fmt.Fprintf(server, "* %d EXISTS\r\n* OK [UIDVALIDITY %d] stable\r\n%s OK [READ-ONLY] done\r\n", total, validity, tag)
				case strings.HasPrefix(line, tag+" UID SEARCH "):
					var ids []string
					for i := 1; i <= total; i++ {
						ids = append(ids, fmt.Sprint(i))
					}
					_, _ = fmt.Fprintf(server, "* SEARCH %s\r\n%s OK done\r\n", strings.Join(ids, " "), tag)
				case strings.HasPrefix(line, tag+" UID FETCH ") && strings.Contains(line, "BODY.PEEK[]"):
					id := fields[3]
					_, _ = fmt.Fprintf(server, "* %s FETCH (UID %s FLAGS (\\Seen) INTERNALDATE \"02-Jan-2019 13:04:05 +0200\" BODY[]<0> {%d}\r\n%s)\r\n%s OK done\r\n", id, id, len(mail), mail, tag)
				default:
					t.Errorf("unexpected IMAP command: %s", line)
					_, _ = fmt.Fprintf(server, "%s BAD unexpected\r\n", tag)
				}
			}
		}()
		client := imapclient.New(app, nil)
		var received []string
		prev, err := copyFolder(t.Context(), client, "INBOX", "a", "dest", dir, "server", []byte("local key"), func(name string, raw []byte, info MessageInfo, readErr error) error {
			if readErr != nil {
				return readErr
			}
			if !info.Read || info.Date.Year() != 2019 || len(info.SourceKey) != 32 {
				return errors.New("lost IMAP metadata")
			}
			if !bytes.Equal(raw, mail) {
				return errors.New("incorrect mail body")
			}
			if interrupt && len(received) == 1 {
				return context.Canceled
			}
			received = append(received, name)
			return nil
		}, nil, func(string) {})
		_ = client.Close()
		<-done
		return received, prev, err
	}
	if got, _, err := transfer(2, 1, true); !errors.Is(err, context.Canceled) || len(got) != 1 {
		t.Fatalf("first run: %v, %v", got, err)
	}
	if got, prev, err := transfer(3, 1, false); err != nil || prev != 1 || !slices.Equal(got, []string{"INBOX UID 2", "INBOX UID 3"}) {
		t.Fatalf("resume: %v %d %v", got, prev, err)
	}
	if got, prev, err := transfer(3, 2, false); err != nil || prev != 0 || len(got) != 3 {
		t.Fatalf("uid reset: %v %d %v", got, prev, err)
	}
}

func TestServerAddress(t *testing.T) {
	for _, c := range [][2]string{{"", ""}, {"http://example.com", ""}, {"example.com:0", ""}, {"name@example.com", ""}, {"example.com:bad", ""}, {"example.com", "0"}, {"example.com", "70000"}, {"example.com", "abc"}, {"example.com:993", "143"}} {
		if _, err := serverAddress(c[0], c[1]); err == nil {
			t.Fatalf("accepted %q port %q", c[0], c[1])
		}
	}
	for c, want := range map[[2]string]string{
		{"imap.example.test", ""}:        "imap.example.test:993",
		{"imap.example.test", "143"}:     "imap.example.test:143",
		{" imap.example.test ", "1143"}:  "imap.example.test:1143",
		{"imap.example.test:993", "993"}: "imap.example.test:993",
		{"[::1]:123", ""}:                "[::1]:123",
		{"::1", "993"}:                   "[::1]:993",
	} {
		if got, err := serverAddress(c[0], c[1]); err != nil || got != want {
			t.Fatalf("%q port %q -> %q, %v", c[0], c[1], got, err)
		}
	}
	for c, want := range map[[2]string]bool{{"", "143"}: true, {"", "993"}: false, {SecurityTLS, "143"}: false, {SecurityStartTLS, "993"}: true} {
		if got, err := useStartTLS(c[0], c[1]); err != nil || got != want {
			t.Fatalf("security %q port %q -> %t, %v", c[0], c[1], got, err)
		}
	}
	if _, err := useStartTLS("plain", "143"); err == nil {
		t.Fatal("accepted an unknown connection security")
	}
}

func TestWholeMailbox(t *testing.T) {
	dir := t.TempDir()
	key := []byte("local fixture")
	raw := "Subject: One message in two folders\r\nMessage-ID: <repeat@example.test>\r\n\r\nHello.\r\n"
	type result struct {
		folder Folder
		info   MessageInfo
	}
	run := func() ([]Folder, []result, int) {
		t.Helper()
		app, server := net.Pipe()
		_ = app.SetDeadline(time.Now().Add(4 * time.Second))
		_ = server.SetDeadline(time.Now().Add(4 * time.Second))
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() { _ = server.Close() }()
			_, _ = fmt.Fprint(server, "* PREAUTH [CAPABILITY IMAP4rev1 SPECIAL-USE] ready\r\n")
			scan := bufio.NewScanner(server)
			var folder string
			for scan.Scan() {
				line := scan.Text()
				fields := strings.Fields(line)
				tag := fields[0]
				switch {
				case fields[1] == "LIST" && strings.Contains(line, "RETURN (SPECIAL-USE)"):
					_, _ = fmt.Fprint(server, "* LIST () \".\" INBOX\r\n* LIST (\\Sent) \".\" INBOX.Enviados\r\n* LIST (\\Noselect) \".\" INBOX.Clients\r\n* LIST () \".\" INBOX.Clients.Azul\r\n* LIST () \".\" INBOX.Empty\r\n* LIST (\\All) \".\" INBOX.All\r\n* LIST (\\Flagged) \".\" INBOX.Starred\r\n")
				case fields[1] == "EXAMINE":
					folder = strings.Trim(fields[2], "\"")
					n := 1
					if folder == "INBOX.Empty" {
						n = 0
					}
					_, _ = fmt.Fprintf(server, "* %d EXISTS\r\n* OK [UIDVALIDITY 42] stable\r\n", n)
				case strings.Contains(line, "UID SEARCH "):
					ids := " 7"
					if folder == "INBOX.Empty" {
						ids = ""
					}
					_, _ = fmt.Fprintf(server, "* SEARCH%s\r\n", ids)
				case strings.Contains(line, "UID FETCH ") && strings.Contains(line, "BODY.PEEK[]") && strings.Contains(line, "FLAGS") && strings.Contains(line, "INTERNALDATE"):
					flags := ""
					if folder == "INBOX.Enviados" {
						flags = "\\Seen \\Flagged"
					}
					_, _ = fmt.Fprintf(server, "* 1 FETCH (UID 7 FLAGS (%s) INTERNALDATE \"01-Jan-2020 10:00:00 +0000\" BODY[]<0> {%d}\r\n%s)\r\n", flags, len(raw), raw)
				default:
					t.Errorf("unexpected command: %s", line)
				}
				_, _ = fmt.Fprintf(server, "%s OK done\r\n", tag)
			}
		}()
		client := imapclient.New(app, nil)
		var opened []Folder
		var copied []result
		count, err := copyMailbox(t.Context(), client, IMAPAccount{Username: "owner"}, "dest", dir, "imap.hostinger.com:993", key, func(f Folder) (IMAPVisit, error) {
			opened = append(opened, f)
			return func(_ string, b []byte, info MessageInfo, err error) error {
				if string(b) != raw {
					t.Error("changed message bytes")
				}
				copied = append(copied, result{f, info})
				return err
			}, nil
		}, nil, func(string) {})
		_ = client.Close()
		<-done
		if err != nil {
			t.Fatal(err)
		}
		return opened, copied, count
	}
	opened, copied, previous := run()
	if len(opened) != 4 || len(copied) != 3 || previous != 0 {
		t.Fatalf("opened %v, copied %d, previously imported %d", opened, len(copied), previous)
	}
	seen := map[string]bool{}
	for _, msg := range copied {
		if seen[string(msg.info.SourceKey)] {
			t.Fatal("distinct copies have identical source keys")
		}
		seen[string(msg.info.SourceKey)] = true
		switch msg.folder.Name {
		case "INBOX.Enviados":
			if msg.folder.Mailbox != "sent" || !msg.info.Read || !msg.info.Starred {
				t.Fatal("lost localized Sent role or seen flag")
			}
		case "INBOX.Clients.Azul":
			if msg.folder.Mailbox != "folder" || !slices.Equal(msg.folder.Path, []string{"Clients", "Azul"}) || msg.info.Read {
				t.Fatal("lost nested folder or unread status")
			}
		case "INBOX":
			if msg.folder.Mailbox != "inbox" || msg.info.Read {
				t.Fatal("lost inbox or unread status")
			}
		default:
			t.Fatal(msg.folder)
		}
	}
	if opened, copied, n := run(); len(opened) != 4 || len(copied) != 0 || n != 3 {
		t.Fatal("retry did not resume across all four source folders")
	}
}

func TestSourceRoleFallback(t *testing.T) {
	list := []*imap.ListData{{Mailbox: "Sent", Delim: '/'}, {Mailbox: "Clients/Sent", Delim: '/'}, {Mailbox: "Inbox", Delim: '/'}, {Mailbox: "Clients.Archive", Delim: 0}}
	folders := folderPlan(list)
	want := map[string]string{"Sent": "sent", "Clients/Sent": "folder", "Inbox": "inbox", "Clients.Archive": "folder"}
	for _, f := range folders {
		if want[f.Name] != f.Mailbox {
			t.Fatalf("%s became %s", f.Name, f.Mailbox)
		}
	}
	list = append(list, &imap.ListData{Mailbox: "Sortie", Attrs: []imap.MailboxAttr{imap.MailboxAttrSent}})
	for _, f := range folderPlan(list) {
		if f.Name == "Sent" && f.Mailbox != "folder" {
			t.Fatal("a custom folder overrode a server-advertised Sent folder")
		}
	}
}
