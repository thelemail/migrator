package destination

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
	"testing"
	"time"

	"github.com/thelemail/migrator/engine/internal/session"
	"github.com/thelemail/trust/attframe"
	"github.com/thelemail/trust/pgp"
)

var example = []byte(strings.Join([]string{
	"From: Alice <alice@example.org>", "To: Bob <bob@example.net>", "Bcc: hidden@example.org",
	"Date: Wed, 2 Jan 2019 13:04:05 +0200", "Subject: =?UTF-8?Q?Ol=C3=A1?=", "Message-ID: <example@example.org>",
	"References: <older@example.org> <parent@example.org>", "In-Reply-To: <parent@example.org>", "X-Original: preserved",
	"Content-Type: multipart/mixed; boundary=outer", "", "--outer", "Content-Type: multipart/related; boundary=inner", "",
	"--inner", "Content-Type: text/html", "", "<p>Hello reader</p><img src=\"cid:logo\">", "--inner", "Content-Type: image/png",
	"Content-Disposition: inline", "Content-ID: <logo>", "Content-Transfer-Encoding: base64", "", "aW1hZ2U=", "--inner--",
	"--outer", "Content-Type: application/octet-stream", "Content-Disposition: attachment; filename*=utf-8''notes%20file.bin",
	"Content-Transfer-Encoding: base64", "", "AAECA/8=", "--outer--", "",
}, "\r\n"))

func TestImportWireRoundTrip(t *testing.T) {
	key, err := pgp.Generate("Bob", "bob@example.org", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.ArmorPublic()
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := hex.DecodeString(key.Fingerprint())
	s := &session.Session{PublicKeyArmored: public, Fingerprint: fp, AccountID: "bob", BaseURL: "https://api.example.test"}
	blobs := make(map[string][]byte)
	slots := make(map[string]uploadSlot)
	var in importRequest
	imported := false
	starred := false
	rejectPlacement := false
	attempts := 0
	const storedID = "9c89c472-e461-49d2-afde-a6f556c295c7"
	fake := func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api.example.test" {
			t.Fatalf("unexpected destination %s", req.URL.Host)
		}
		var response any
		switch req.Method + " " + req.URL.Path {
		case "POST /v1/attachments/upload-urls":
			var grants struct{ Slots []uploadSlot }
			if err := json.NewDecoder(req.Body).Decode(&grants); err != nil {
				t.Fatal(err)
			}
			slot := grants.Slots[0]
			if slot.Role != "sender" || !bytes.Equal(slot.Fingerprint, fp) {
				t.Fatal("slot did not bind to mailbox key")
			}
			slots[slot.ID] = slot
			response = map[string]any{"slots": []uploadGrant{{slot.ID, slot.ID, "/v1/attachments/uploads?objectKey=" + slot.ID}}}
		case "PUT /v1/attachments/uploads":
			id := req.URL.Query().Get("objectKey")
			blobs[id], err = io.ReadAll(req.Body)
			if err != nil || len(blobs[id]) != slots[id].Size || !bytes.Equal(digest(blobs[id]), slots[id].SHA) {
				t.Fatal("ciphertext did not match the slot")
			}
		case "POST /v1/messages/import":
			attempts++
			if rejectPlacement {
				return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			in = importRequest{}
			if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
				t.Fatal(err)
			}
			response = map[string]any{"messageId": storedID, "existing": imported}
			imported = true
		case "POST /v1/messages/" + storedID + "/star":
			starred = true
		default:
			t.Fatalf("unexpected request %v", req.URL)
		}
		b, _ := json.Marshal(response)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b))}, nil
	}
	c := client{s, fake}
	existing, err := c.importMessage(context.Background(), example, nil, time.Time{})
	if err != nil || existing {
		t.Fatalf("import: existing=%t, err=%v", existing, err)
	}
	if len(in.Attachments) != 1 || in.ExternalID != "<example@example.org>" || in.InReplyTo != "<parent@example.org>" || len(in.References) != 2 || !bytes.Equal(in.ContentHash, digest(example)) {
		t.Fatal("import is missing attachments, original threading or content hash")
	}
	if got := in.StoredAt.Format(time.RFC3339); got != "2019-01-02T11:04:05Z" {
		t.Fatalf("lost original date: %s", got)
	}
	decrypt := func(cipher []byte) []byte {
		t.Helper()
		opened, err := pgp.Decrypt([]*pgp.Key{key}, cipher, nil)
		if err != nil {
			t.Fatal(err)
		}
		return opened.Data
	}
	body := string(decrypt(blobs[in.Sent.BodyObjectKey]))
	for _, unchanged := range []string{"X-Original: preserved", "Bcc: hidden@example.org", "aW1hZ2U=", "cid:logo", "<example@example.org>"} {
		if !strings.Contains(body, unchanged) {
			t.Fatalf("body lost %q", unchanged)
		}
	}
	if strings.Contains(body, "AAECA/8=") {
		t.Fatal("stored a duplicate copy of regular attachment bytes")
	}
	var p preview
	if err := json.Unmarshal(decrypt(in.Sent.Preview), &p); err != nil || p.Subject != "Olá" || len(p.Recipients) != 2 || p.Snippet != "Hello reader" || !p.Flags["imported"] {
		t.Fatalf("incorrect preview: %+v, err=%v", p, err)
	}
	f := in.Attachments[0]
	header, payload, err := attframe.Parse(decrypt(blobs[f.ObjectKey]))
	if err != nil || header.Filename != "notes file.bin" || !bytes.Equal(payload, []byte{0, 1, 2, 3, 255}) || !bytes.Equal(header.PlaintextSHA256, digest(payload)) {
		t.Fatalf("attachment changed: %s %x %v", header.Filename, payload, err)
	}
	if existing, err := c.importMessage(context.Background(), example, nil, time.Time{}); err != nil || !existing {
		t.Fatalf("re-import: existing=%t, err=%v", existing, err)
	}
	if in.Placement != nil {
		t.Fatal("file import sent IMAP placement")
	}
	date := time.Date(2020, 8, 5, 12, 15, 0, 0, time.UTC)
	for _, mailbox := range []string{"sent", "folder", "inbox"} {
		p := Placement{Mailbox: mailbox, Read: mailbox == "sent", Starred: mailbox == "sent", SourceKey: digest([]byte(mailbox))}
		if mailbox == "folder" {
			p.FolderID = "nested"
		}
		if _, err := c.importMessage(t.Context(), example, &p, date); err != nil {
			t.Fatal(err)
		}
		if starred {
			t.Error("the star was set by a separate request")
		}
		if in.Placement == nil || in.Placement.Starred != p.Starred || !bytes.Equal(in.Placement.SourceKey, p.SourceKey) || in.Placement.Read != p.Read || in.Placement.Mailbox != mailbox || in.Placement.FolderID != p.FolderID || !in.StoredAt.Equal(date) {
			t.Fatal("source placement did not survive message upload")
		}
	}

	rejectPlacement = true
	prior := attempts
	_, err = c.importMessage(t.Context(), example, &Placement{Mailbox: "sent", SourceKey: digest([]byte("source"))}, date)
	if err == nil || !errors.Is(err, StatusError(400)) || attempts != prior+1 {
		t.Fatalf("failed placement was retried or reported as successful: %v", err)
	}

}

func TestRejectRedirectedGrantAndInvalidArchives(t *testing.T) {
	s := client{Session: &session.Session{BaseURL: "https://api.example.test"}, do: func(req *http.Request) (*http.Response, error) {
		if req.Method != "POST" {
			t.Fatal("sent data outside the API")
		}
		var in struct{ Slots []uploadSlot }
		_ = json.NewDecoder(req.Body).Decode(&in)
		b := fmt.Sprintf(`{"slots":[{"slotId":%q,"objectKey":"key","putPath":"https://elsewhere.test/v1/attachments/uploads?objectKey=key"}]}`, in.Slots[0].ID)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(b))}, nil
	}}
	if _, err := s.upload(context.Background(), 0, []byte("ciphertext")); err == nil {
		t.Fatal("accepted foreign upload grant")
	}
	for _, data := range [][]byte{[]byte("not an email"), bytes.Replace(example, []byte("AAECA/8="), []byte("BAD#"), 1), bytes.Replace(example, []byte("--outer--"), []byte("missing delimiter"), 1)} {
		if _, err := parseMessage(context.Background(), data, time.Time{}); err == nil {
			t.Fatal("accepted malformed message without reporting failure")
		}
	}
}

func TestPreservesUnmodifiedMIMEAndSignedBytes(t *testing.T) {
	for _, raw := range [][]byte{[]byte("Subject: Just a header\r\n"), []byte("Subject: plain\n\nhello!"), bytes.Replace(example, []byte("multipart/mixed"), []byte("multipart/signed"), 1)} {
		m, err := parseMessage(context.Background(), raw, time.Time{})
		if err != nil || !bytes.Equal(raw, m.body) {
			t.Fatalf("MIME bytes changed: %v", err)
		}
	}
}

func TestSeparateMessageFailuresFromStoppedTransfers(t *testing.T) {
	s := &session.Session{AccountID: "owner"}
	for _, raw := range [][]byte{nil, []byte("corrupt header"), bytes.Replace(example, []byte("AAECA/8="), []byte("#"), 1)} {
		if _, err := Import(context.Background(), s, raw, nil, time.Time{}); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("per-message failure was not classified: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Import(ctx, s, example, nil, time.Time{}); !errors.Is(err, context.Canceled) || errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("cancellation was incorrectly classified: %v", err)
	}
	if _, err := Import(context.Background(), s, example, nil, time.Time{}); err == nil || errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unusable destination key was incorrectly classified: %v", err)
	}
}
