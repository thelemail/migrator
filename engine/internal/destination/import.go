package destination

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/thelemail/migrator/engine/internal/session"
	"github.com/thelemail/trust/attframe"
	"github.com/thelemail/trust/pgp"
)

var (
	ErrInvalidMessage = errors.New("unsupported message")
	ErrFolderRejected = errors.New("the destination no longer has this folder or label")
)

type cipherInfo struct {
	Ordinal     int    `json:"ordinal"`
	Size        int    `json:"ciphertextSizeBytes"`
	SHA         []byte `json:"ciphertextSha256"`
	Fingerprint []byte `json:"keyFingerprint"`
}

type uploadSlot struct {
	cipherInfo
	ID   string `json:"slotId"`
	Role string `json:"role"`
}

type uploadGrant struct {
	ID        string `json:"slotId"`
	ObjectKey string `json:"objectKey"`
	PutPath   string `json:"putPath"`
}

type descriptor struct {
	cipherInfo
	ObjectKey     string `json:"objectKey"`
	Inline        bool   `json:"isInline"`
	ContentIDHash []byte `json:"contentIdHash,omitempty"`
}

type envelope struct {
	Preview            []byte `json:"encryptedPreview"`
	PreviewFingerprint []byte `json:"previewKeyFingerprint"`
	BodyObjectKey      string `json:"bodyObjectKey"`
	BodyFingerprint    []byte `json:"bodyKeyFingerprint"`
	BodySHA            []byte `json:"bodySha256"`
	BodySize           int    `json:"bodySizeBytes"`
}

type Placement struct {
	Starred   bool     `json:"starred"`
	Mailbox   string   `json:"mailbox"`
	FolderID  string   `json:"folderId,omitempty"`
	LabelIDs  []string `json:"labelIds,omitempty"`
	Read      bool     `json:"read"`
	SourceKey []byte   `json:"sourceKey"`
}

type importRequest struct {
	Placement   *Placement   `json:"placement,omitempty"`
	Version     int          `json:"schemaVersion"`
	StoredAt    time.Time    `json:"storedAt"`
	ExternalID  string       `json:"externalMessageId,omitempty"`
	ContentHash []byte       `json:"contentHash"`
	InReplyTo   string       `json:"inReplyToHeader,omitempty"`
	References  []string     `json:"references,omitempty"`
	Sent        envelope     `json:"sent"`
	Attachments []descriptor `json:"attachments"`
}

func digest(b []byte) []byte {
	hash := sha256.Sum256(b)
	return hash[:]
}

type client struct {
	*session.Session
	do func(*http.Request) (*http.Response, error)
}

func Import(ctx context.Context, s *session.Session, raw []byte, placement *Placement, internalDate time.Time) (bool, error) {
	if s == nil || s.AccountID == "" {
		return false, fmt.Errorf("sign in to the destination mailbox first")
	}
	return (client{s, s.Do}).importMessage(ctx, raw, placement, internalDate)
}

func (s client) importMessage(ctx context.Context, raw []byte, placement *Placement, internalDate time.Time) (bool, error) {
	m, err := parseMessage(ctx, raw, internalDate)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	key, err := pgp.ParseKey(s.PublicKeyArmored)
	if err != nil || key.IsPrivate() || key.Fingerprint() != hex.EncodeToString(s.Fingerprint) {
		return false, fmt.Errorf("destination mailbox public key does not match its fingerprint")
	}
	encrypt := func(data []byte) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return pgp.Encrypt(data, []*pgp.Key{key}, nil, false)
	}
	data, err := json.Marshal(m.preview)
	if err != nil {
		return false, fmt.Errorf("encode mailbox preview: %w", err)
	}
	previewCipher, err := encrypt(data)
	if err != nil {
		return false, err
	}
	if len(previewCipher) > 64<<10 {
		return false, fmt.Errorf("%w: preview exceeds the destination's 64 KiB limit", ErrInvalidMessage)
	}
	bodyCipher, err := encrypt(m.body)
	if err != nil {
		return false, err
	}
	body, err := s.upload(ctx, 0, bodyCipher)
	if err != nil {
		return false, fmt.Errorf("upload message body: %w", err)
	}
	req := importRequest{
		Placement: placement, Version: 1, StoredAt: m.preview.Date, ContentHash: digest(raw),
		ExternalID: m.header.Get("Message-ID"), InReplyTo: m.header.Get("In-Reply-To"),
		References:  strings.Fields(m.header.Get("References")),
		Sent:        envelope{previewCipher, s.Fingerprint, body.ObjectKey, s.Fingerprint, body.SHA, body.Size},
		Attachments: make([]descriptor, 0, len(m.files)),
	}
	if !internalDate.IsZero() {
		req.StoredAt = internalDate.UTC()
	}
	if len(req.References) > 64 {
		req.References = req.References[len(req.References)-64:]
	}
	for i, file := range m.files {
		frame, err := attframe.Build(file.header, file.payload)
		if err != nil {
			return false, fmt.Errorf("%w: prepare attachment %d: %v", ErrInvalidMessage, i+1, err)
		}
		cipher, err := encrypt(frame)
		if err != nil {
			return false, err
		}
		d, err := s.upload(ctx, i, cipher)
		if err != nil {
			return false, fmt.Errorf("upload attachment %d: %w", i+1, err)
		}
		d.Inline = file.header.Disposition == attframe.DispositionInline
		if file.header.ContentID != "" {
			d.ContentIDHash = digest([]byte(file.header.ContentID))
		}
		req.Attachments = append(req.Attachments, d)
	}
	var result struct {
		MessageID string `json:"messageId"`
		Existing  *bool  `json:"existing"`
	}
	if err := s.post(ctx, "/v1/messages/import", req, &result); err != nil {
		if placement != nil && errors.Is(err, StatusError(http.StatusNotFound)) {
			return false, fmt.Errorf("%w (%w)", ErrFolderRejected, err)
		}
		return false, fmt.Errorf("save imported message: %w", err)
	}
	if result.Existing == nil || result.MessageID == "" {
		return false, fmt.Errorf("destination did not confirm the imported message")
	}
	if _, err := uuid.Parse(result.MessageID); err != nil {
		return false, errors.New("destination returned an invalid message ID")
	}
	return *result.Existing, nil
}

func Imported(ctx context.Context, s *session.Session, keys [][]byte) (map[string]bool, error) {
	return client{s, s.Do}.imported(ctx, keys)
}

func (c client) imported(ctx context.Context, keys [][]byte) (map[string]bool, error) {
	known := make(map[string]bool, len(keys))
	for start := 0; start < len(keys); start += lookupBatch {
		batch := keys[start:min(start+lookupBatch, len(keys))]
		var out struct {
			Existing [][]byte `json:"existing"`
		}
		if err := c.post(ctx, "/v1/messages/import/lookup", map[string][][]byte{"sourceKeys": batch}, &out); err != nil {
			return nil, fmt.Errorf("check already imported messages: %w", err)
		}
		for _, k := range out.Existing {
			known[string(k)] = true
		}
	}
	return known, nil
}

const lookupBatch = 500

func (s client) upload(ctx context.Context, ordinal int, cipher []byte) (descriptor, error) {
	info := cipherInfo{Ordinal: ordinal, Size: len(cipher), SHA: digest(cipher), Fingerprint: s.Fingerprint}
	slotID := uuid.NewString()
	var grants struct {
		Slots []uploadGrant `json:"slots"`
	}
	if err := s.post(ctx, "/v1/attachments/upload-urls", map[string][]uploadSlot{"slots": {{info, slotID, "sender"}}}, &grants); err != nil {
		return descriptor{}, err
	}
	if len(grants.Slots) != 1 || grants.Slots[0].ID != slotID || grants.Slots[0].ObjectKey == "" {
		return descriptor{}, fmt.Errorf("invalid upload grant")
	}
	g := grants.Slots[0]
	u, err := url.ParseRequestURI(g.PutPath)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path != "/v1/attachments/uploads" || u.Query().Get("objectKey") != g.ObjectKey {
		return descriptor{}, fmt.Errorf("invalid attachment upload destination")
	}
	if err := s.request(ctx, http.MethodPut, g.PutPath, "application/octet-stream", cipher, nil); err != nil {
		return descriptor{}, err
	}
	return descriptor{cipherInfo: info, ObjectKey: g.ObjectKey}, nil
}

func (s client) post(ctx context.Context, path string, data, out any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.request(ctx, http.MethodPost, path, "application/json", b, out)
}

func (s client) request(ctx context.Context, method, path, contentType string, data []byte, out any) error {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.BaseURL, "/")+path, bytes.NewReader(data))
		if err != nil {
			return err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := s.do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			defer func() { _ = resp.Body.Close() }()
			if out != nil && json.NewDecoder(io.LimitReader(resp.Body, 48<<20)).Decode(out) != nil {
				return fmt.Errorf("invalid response from destination")
			}
			return nil
		}
		_ = resp.Body.Close()
		if attempt < 4 && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) {
			wait := retryDelay(resp.Header.Get("Retry-After"), attempt)
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
				continue
			}
		}
		return StatusError(resp.StatusCode)
	}
}

type StatusError int

func (status StatusError) Error() string {
	switch int(status) {
	case http.StatusUnauthorized:
		return "the destination session expired; sign in again to continue"
	case http.StatusInsufficientStorage:
		return "the destination mailbox has insufficient storage; free space and retry"
	case http.StatusRequestEntityTooLarge:
		return "the destination could not accept an object this large"
	}
	return fmt.Sprintf("destination returned HTTP %d (%s)", status, http.StatusText(int(status)))
}

func retryDelay(value string, attempt int) time.Duration {
	if sec, err := strconv.ParseInt(value, 10, 32); err == nil && sec >= 0 {
		return time.Duration(sec) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		return max(time.Until(t), 0)
	}
	return (1 << attempt) * time.Second
}
