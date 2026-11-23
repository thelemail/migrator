package source

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"
)

func serverAddress(server, port string) (string, error) {
	server = strings.TrimSpace(server)
	port = strings.TrimSpace(port)
	if server == "" || strings.ContainsAny(server, "/@?# \t\r\n") {
		return "", errors.New("enter the IMAP server name, for example imap.example.com")
	}
	if host, given, err := net.SplitHostPort(server); err == nil {
		if port != "" && port != given {
			return "", errors.New("enter the port in the Port field only")
		}
		server, port = host, given
	} else if strings.Contains(server, ":") && net.ParseIP(server) == nil {
		return "", errors.New("invalid IMAP server name")
	}
	if port == "" {
		port = "993"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("enter a port number between 1 and 65535")
	}
	return net.JoinHostPort(server, strconv.Itoa(n)), nil
}

type IMAPAccount struct{ Server, Port, Security, Username, Password string }

const (
	SecurityTLS      = "tls"
	SecurityStartTLS = "starttls"
)

var ErrSourceSignIn = errors.New("the source mailbox did not accept the sign-in")

type SignInError struct {
	Host string
	Err  error
}

func (e *SignInError) Error() string { return fmt.Sprintf("%v: %v", ErrSourceSignIn, e.Err) }

func (e *SignInError) Unwrap() []error { return []error{ErrSourceSignIn, e.Err} }

type ConnectError struct {
	Address  string
	StartTLS bool
	Err      error
}

func (e *ConnectError) Error() string { return fmt.Sprintf("connect to IMAP %s: %v", e.Address, e.Err) }

func (e *ConnectError) Unwrap() error { return e.Err }

const startTLSPort = "143"

var trustedRoots *x509.CertPool

func useStartTLS(security, port string) (bool, error) {
	switch security {
	case SecurityStartTLS:
		return true, nil
	case SecurityTLS:
		return false, nil
	case "":
		return port == startTLSPort, nil
	}
	return false, errors.New("choose SSL/TLS or STARTTLS")
}

func connectIMAP(ctx context.Context, account IMAPAccount) (*imapclient.Client, func(), string, error) {
	address, err := serverAddress(account.Server, account.Port)
	if err != nil {
		return nil, nil, "", err
	}
	_, port, _ := net.SplitHostPort(address)
	startTLS, err := useStartTLS(account.Security, port)
	if err != nil {
		return nil, nil, "", err
	}
	return connectWith(ctx, IMAPAccount{Server: address, Username: account.Username, Password: account.Password}, startTLS)
}

type Summary struct {
	Address  string
	StartTLS bool
	Folders  int
	Messages int
}

func Check(ctx context.Context, account IMAPAccount) (Summary, error) {
	client, closeClient, address, err := connectIMAP(ctx, account)
	if err != nil {
		return Summary{}, err
	}
	defer closeClient()
	_, port, _ := net.SplitHostPort(address)
	startTLS, _ := useStartTLS(account.Security, port)
	opts := &imap.ListOptions{ReturnSpecialUse: client.Caps().Has(imap.CapSpecialUse)}
	list, err := client.List("", "*", opts).Collect()
	if err != nil {
		return Summary{}, fmt.Errorf("list source folders: %w", err)
	}
	folders := folderPlan(list)
	if len(folders) == 0 {
		return Summary{}, errors.New("the source server returned no selectable mail folders")
	}
	summary := Summary{Address: address, StartTLS: startTLS, Folders: len(folders)}
	for _, folder := range folders {
		if err := ctx.Err(); err != nil {
			return Summary{}, err
		}
		status, err := client.Status(folder.Name, &imap.StatusOptions{NumMessages: true}).Wait()
		if err != nil {
			return Summary{}, fmt.Errorf("count messages in %q: %w", folder.Name, err)
		}
		if status.NumMessages != nil {
			summary.Messages += int(*status.NumMessages)
		}
	}
	_ = client.Logout().Wait()
	return summary, nil
}

func connectWith(ctx context.Context, account IMAPAccount, startTLS bool) (*imapclient.Client, func(), string, error) {
	address := account.Server
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, nil, "", err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: trustedRoots}
	dialer := &net.Dialer{Timeout: 20 * time.Second}
	var conn net.Conn
	if startTLS {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	} else {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, nil, "", &ConnectError{Address: address, StartTLS: startTLS, Err: err}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	var client *imapclient.Client
	if startTLS {
		client, err = imapclient.NewStartTLS(conn, &imapclient.Options{TLSConfig: tlsConfig})
		if err != nil {
			stop()
			return nil, nil, "", &ConnectError{Address: address, StartTLS: true, Err: fmt.Errorf("start TLS: %w", err)}
		}
	} else {
		client = imapclient.New(conn, nil)
	}
	closeClient := func() { stop(); _ = client.Close() }
	if err := signIn(client, account); err != nil {
		closeClient()
		return nil, nil, "", &SignInError{Host: host, Err: err}
	}
	return client, closeClient, address, nil
}

func signIn(client *imapclient.Client, account IMAPAccount) error {
	caps := client.Caps()
	if caps.Has(imap.AuthCap(sasl.Plain)) || caps.Has(imap.CapLoginDisabled) {
		return client.Authenticate(sasl.NewPlainClient("", account.Username, account.Password))
	}
	return client.Login(account.Username, account.Password).Wait()
}

type Folder struct {
	Name    string
	Mailbox string
	Path    []string
	Color   string
}

type Label struct {
	Path  []string
	Color string
}

type MessageInfo struct {
	Starred   bool
	Read      bool
	Date      time.Time
	SourceKey []byte
	Labels    []Label
}

type Known func(keys [][]byte) (map[string]bool, error)

type IMAPVisit func(name string, raw []byte, info MessageInfo, err error) error
type OpenFolder func(Folder) (IMAPVisit, error)

func Identity(key []byte, parts ...string) []byte {
	data, _ := json.Marshal(parts)
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func mailboxRole(attrs []imap.MailboxAttr) string {
	for _, attr := range attrs {
		switch strings.ToLower(string(attr)) {
		case `\sent`:
			return "sent"
		case `\archive`:
			return "archive"
		case `\trash`:
			return "trash"
		case `\junk`:
			return "spam"
		}
	}
	return ""
}

var skippedAttrs = []imap.MailboxAttr{
	imap.MailboxAttrNoSelect, imap.MailboxAttrNonExistent,
	imap.MailboxAttrAll, imap.MailboxAttrFlagged, imap.MailboxAttrImportant,
}

func folderPlan(list []*imap.ListData) []Folder {
	advertised := map[string]bool{}
	inboxNamespace := true
	for _, f := range list {
		advertised[mailboxRole(f.Attrs)] = true
		if !strings.EqualFold(f.Mailbox, "inbox") && (f.Delim == 0 || !strings.HasPrefix(strings.ToLower(f.Mailbox), "inbox"+string(f.Delim))) {
			inboxNamespace = false
		}
	}
	var folders []Folder
	for _, f := range list {
		if slices.ContainsFunc(f.Attrs, func(a imap.MailboxAttr) bool { return slices.Contains(skippedAttrs, a) }) {
			continue
		}
		path := []string{f.Mailbox}
		if f.Delim != 0 {
			path = strings.Split(f.Mailbox, string(f.Delim))
		}
		inboxChild := len(path) > 1 && strings.EqualFold(path[0], "INBOX")
		role := mailboxRole(f.Attrs)
		if strings.EqualFold(f.Mailbox, "INBOX") {
			role = "inbox"
		} else if role == "" && (len(path) == 1 || (inboxChild && len(path) == 2)) {
			var guess string
			switch strings.ToLower(path[len(path)-1]) {
			case "sent", "sent items", "sent mail", "sent messages":
				guess = "sent"
			case "archive", "archives":
				guess = "archive"
			case "trash", "deleted items", "deleted messages":
				guess = "trash"
			case "junk", "junk e-mail", "junk email", "spam":
				guess = "spam"
			}
			if !advertised[guess] {
				role = guess
			}
		}
		if inboxNamespace && inboxChild {
			path = path[1:]
		}
		folders = append(folders, Folder{Name: f.Mailbox, Mailbox: cmp.Or(role, "folder"), Path: path})
	}
	slices.SortFunc(folders, func(a, b Folder) int {
		if a.Mailbox == "inbox" && b.Mailbox != "inbox" {
			return -1
		}
		if b.Mailbox == "inbox" && a.Mailbox != "inbox" {
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return folders
}

func IMAP(ctx context.Context, account IMAPAccount, destination, stateDir string, key []byte, open OpenFolder, known Known, progress func(string)) (int, error) {
	client, closeClient, address, err := connectIMAP(ctx, account)
	if err != nil {
		return 0, err
	}
	defer closeClient()
	return copyMailbox(ctx, client, account, destination, stateDir, address, key, open, known, progress)
}

func copyMailbox(ctx context.Context, client *imapclient.Client, account IMAPAccount, destination, stateDir, address string, key []byte, open OpenFolder, known Known, progress func(string)) (int, error) {
	opts := &imap.ListOptions{ReturnSpecialUse: client.Caps().Has(imap.CapSpecialUse)}
	list, err := client.List("", "*", opts).Collect()
	if err != nil {
		return 0, fmt.Errorf("list source folders: %w", err)
	}
	folders := folderPlan(list)
	if len(folders) == 0 {
		return 0, errors.New("the source server returned no selectable mail folders")
	}
	var previous int
	for i, folder := range folders {
		if err := ctx.Err(); err != nil {
			return previous, err
		}
		progress(fmt.Sprintf("Folder %d of %d · %s", i+1, len(folders), folder.Name))
		visit, err := open(folder)
		if err != nil {
			return previous, fmt.Errorf("prepare %q: %w", folder.Name, err)
		}
		n, err := copyFolder(ctx, client, folder.Name, account.Username, destination, stateDir, address, key, visit, known, progress)
		previous += n
		if err != nil {
			return previous, fmt.Errorf("%s: %w", folder.Name, err)
		}
	}
	return previous, nil
}

func copyFolder(ctx context.Context, client *imapclient.Client, folder, username, destination, stateDir, address string, key []byte, visit IMAPVisit, known Known, progress func(string)) (previous int, err error) {
	mailbox, err := client.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return 0, fmt.Errorf("open source folder: %w", err)
	}
	if mailbox.UIDValidity == 0 {
		return 0, errors.New("source server did not confirm UIDVALIDITY")
	}
	ids, err := client.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("list messages: %w", err)
	}
	cp, err := loadCheckpoint(filepath.Join(stateDir, "imap-placement-v1"), destination, address, username, folder, mailbox.UIDValidity)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, cp.save()) }()
	uids := ids.AllUIDs()
	validity := strconv.FormatUint(uint64(mailbox.UIDValidity), 10)
	sourceKey := func(uid imap.UID) []byte {
		return Identity(key, "message", strings.ToLower(address), username, folder, validity, strconv.FormatUint(uint64(uid), 10))
	}
	if known != nil {
		var pending []imap.UID
		var keys [][]byte
		for _, uid := range uids {
			if !cp.copied.Contains(uid) {
				pending = append(pending, uid)
				keys = append(keys, sourceKey(uid))
			}
		}
		if len(keys) > 0 {
			present, err := known(keys)
			if err != nil {
				return 0, err
			}
			for i, uid := range pending {
				if present[string(keys[i])] {
					cp.copied.AddNum(uid)
					cp.dirty++
				}
			}
		}
	}
	for _, uid := range uids {
		if cp.copied.Contains(uid) {
			previous++
		}
	}
	progress(fmt.Sprintf("%s · %d messages, %d previously copied", folder, len(uids), previous))
	var todo []imap.UID
	for _, uid := range uids {
		if !cp.copied.Contains(uid) {
			todo = append(todo, uid)
		}
	}
	results, stopFetching := prefetch(ctx, client, todo)
	defer stopFetching()
	for next := range results {
		if err := ctx.Err(); err != nil {
			return previous, err
		}
		uid, raw, info, readErr := next.uid, next.raw, next.info, next.err
		name := fmt.Sprintf("%s UID %d", folder, uid)
		if readErr != nil && !errors.Is(readErr, ErrTooLarge) {
			return previous, fmt.Errorf("read %s: %w", name, readErr)
		}
		info.SourceKey = sourceKey(uid)
		if err := visit(name, raw, info, readErr); errors.Is(err, ErrSkipped) {
			continue
		} else if err != nil {
			return previous, err
		}
		if readErr != nil {
			continue
		}
		cp.copied.AddNum(uid)
		cp.dirty++
		if cp.dirty >= 20 {
			if err := cp.save(); err != nil {
				return previous, fmt.Errorf("save transfer progress: %w", err)
			}
		}
	}
	return previous, ctx.Err()
}

const prefetchDepth = 2

type fetched struct {
	uid  imap.UID
	raw  []byte
	info MessageInfo
	err  error
}

func prefetch(ctx context.Context, client *imapclient.Client, uids []imap.UID) (<-chan fetched, func()) {
	ctx, cancel := context.WithCancel(ctx)
	results := make(chan fetched, prefetchDepth)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(results)
		for _, uid := range uids {
			if ctx.Err() != nil {
				return
			}
			raw, info, err := fetchMessage(client, uid)
			select {
			case results <- fetched{uid, raw, info, err}:
			case <-ctx.Done():
				return
			}
			if err != nil && !errors.Is(err, ErrTooLarge) {
				return
			}
		}
	}()
	return results, func() {
		cancel()
		for range results {
		}
		<-done
	}
}

func fetchMessage(client *imapclient.Client, uid imap.UID) ([]byte, MessageInfo, error) {
	part := &imap.FetchItemBodySection{Peek: true, Partial: &imap.SectionPartial{Size: MaxMessageBytes + 1}}
	command := client.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{Flags: true, InternalDate: true, BodySection: []*imap.FetchItemBodySection{part}})
	defer func() { _ = command.Close() }()
	for msg := command.Next(); msg != nil; msg = command.Next() {
		var raw []byte
		var gotFlags bool
		var info MessageInfo
		var received imap.UID
		for item := msg.Next(); item != nil; item = msg.Next() {
			switch value := item.(type) {
			case imapclient.FetchItemDataUID:
				received = value.UID
			case imapclient.FetchItemDataFlags:
				for _, flag := range value.Flags {
					switch {
					case strings.EqualFold(string(flag), string(imap.FlagSeen)):
						info.Read = true
					case strings.EqualFold(string(flag), string(imap.FlagFlagged)):
						info.Starred = true
					}
				}
				gotFlags = true
			case imapclient.FetchItemDataInternalDate:
				info.Date = value.Time
			case imapclient.FetchItemDataBodySection:
				if value.Literal == nil {
					continue
				}
				if value.Literal.Size() > MaxMessageBytes {
					return nil, info, ErrTooLarge
				}
				var err error
				raw, err = io.ReadAll(io.LimitReader(value.Literal, MaxMessageBytes+1))
				if err != nil {
					return nil, info, err
				}
				if len(raw) > MaxMessageBytes {
					return nil, info, ErrTooLarge
				}
			}
		}
		if received != uid || raw == nil {
			continue
		}
		if err := command.Close(); err != nil {
			return nil, info, err
		}
		if !gotFlags {
			return nil, info, errors.New("source server did not return the message read status")
		}
		return raw, info, nil
	}
	if err := command.Close(); err != nil {
		return nil, MessageInfo{}, err
	}
	return nil, MessageInfo{}, errors.New("message is no longer available in the source folder")
}
