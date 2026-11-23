package destination

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"github.com/thelemail/trust/attframe"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

const maxMessageBytes = 50 << 20

type previewParty struct {
	Display string `json:"display"`
	Address string `json:"address"`
	Kind    string `json:"kind,omitempty"`
}

type preview struct {
	Version    int             `json:"v"`
	Subject    string          `json:"subject"`
	Sender     previewParty    `json:"sender"`
	Recipients []previewParty  `json:"recipients"`
	Snippet    string          `json:"snippet"`
	Date       time.Time       `json:"display_date"`
	Flags      map[string]bool `json:"flags"`
}

type attachment struct {
	header  attframe.Header
	payload []byte
}

type message struct {
	preview preview
	header  textproto.MIMEHeader
	body    []byte
	files   []attachment
	parts   int
	plain   string
	html    string
}

var wordDecoder = mime.WordDecoder{CharsetReader: charset.NewReaderLabel}

func parseMessage(ctx context.Context, raw []byte, fallbackDate time.Time) (*message, error) {
	if len(raw) == 0 || len(raw) > maxMessageBytes {
		return nil, fmt.Errorf("message must be between 1 byte and 50 MiB")
	}
	m := &message{}
	body, _, err := m.parsePart(ctx, raw, 0)
	if err != nil {
		return nil, err
	}
	m.body = body
	h := m.header
	date, err := mail.ParseDate(h.Get("Date"))
	if err != nil {
		date = fallbackDate
		if date.IsZero() {
			date = time.Now()
		}
	}
	p := preview{Version: 1, Date: date.UTC(), Subject: decodeWords(h.Get("Subject")), Recipients: []previewParty{}, Flags: map[string]bool{"imported": true}}
	addresses := mail.AddressParser{WordDecoder: &wordDecoder}
	if from, err := addresses.ParseList(h.Get("From")); err == nil && len(from) > 0 {
		p.Sender = previewParty{Display: from[0].Name, Address: from[0].Address}
	}
	for _, kind := range []string{"to", "cc", "bcc"} {
		for _, field := range h.Values(kind) {
			parsed, _ := addresses.ParseList(field)
			for _, addr := range parsed {
				p.Recipients = append(p.Recipients, previewParty{addr.Name, addr.Address, kind})
			}
		}
	}
	p.Snippet = m.plain
	if p.Snippet == "" {
		p.Snippet = m.html
	}
	m.preview = p
	return m, nil
}

func decodeWords(s string) string {
	if decoded, err := wordDecoder.DecodeHeader(s); err == nil {
		return decoded
	}
	return s
}

var headerSeparator = regexp.MustCompile(`\r?\n\r?\n`)

func (m *message) parsePart(ctx context.Context, raw []byte, depth int) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	m.parts++
	if depth > 32 || m.parts > 2000 {
		return nil, false, fmt.Errorf("MIME nesting or part count exceeds the supported limit")
	}
	end := 0
	headerOnly := false
	switch {
	case bytes.HasPrefix(raw, []byte("\r\n")):
		end = 2
	case bytes.HasPrefix(raw, []byte("\n")):
		end = 1
	default:
		sep := headerSeparator.FindIndex(raw)
		if sep == nil {
			end = len(raw)
			headerOnly = true
		} else {
			end = sep[1]
		}
	}
	if end > 1<<20 {
		return nil, false, fmt.Errorf("message header exceeds 1 MiB")
	}
	header := raw[:end]
	if headerOnly {
		header = append(append([]byte(nil), raw...), '\r', '\n', '\r', '\n')
	}
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(header))).ReadMIMEHeader()
	if err != nil {
		return nil, false, fmt.Errorf("invalid message headers")
	}
	if depth == 0 {
		if len(h) == 0 {
			return nil, false, fmt.Errorf("message has no RFC 5322 headers")
		}
		m.header = h
	}
	body := raw[end:]
	ct, params, _ := mime.ParseMediaType(h.Get("Content-Type"))
	if ct == "" {
		ct = "text/plain"
	}
	disposition, dispParams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	name := dispParams["filename"]
	if name == "" {
		name = params["name"]
	}
	cid := strings.Trim(strings.TrimSpace(h.Get("Content-ID")), "<>")
	isFile := disposition == "attachment" || name != "" || (!strings.HasPrefix(ct, "text/") && !strings.HasPrefix(ct, "multipart/"))
	if isFile && (cid == "" || disposition == "attachment") {
		if len(m.files) >= 100 {
			return nil, false, fmt.Errorf("message exceeds 100 attachments")
		}
		reader, err := decodedBody(h, body)
		if err != nil {
			return nil, false, err
		}
		payload, err := io.ReadAll(reader)
		if err != nil {
			return nil, false, fmt.Errorf("invalid attachment transfer encoding")
		}
		if name == "" {
			name = fmt.Sprintf("attachment-%d", len(m.files)+1)
		}
		disp := attframe.DispositionAttachment
		if disposition == "inline" {
			disp = attframe.DispositionInline
		}
		m.files = append(m.files, attachment{attframe.Header{Filename: decodeWords(name), ContentType: ct, ContentID: cid, Disposition: disp, PlaintextSHA256: digest(payload)}, payload})
		return raw, depth > 0, nil
	}
	if strings.HasPrefix(ct, "multipart/") && ct != "multipart/encrypted" {
		replacement, changed, err := m.parseMultipart(ctx, body, params["boundary"], depth)
		if err != nil {
			return nil, false, err
		}
		if changed && ct != "multipart/signed" {
			result := make([]byte, 0, end+len(replacement))
			result = append(result, raw[:end]...)
			return append(result, replacement...), false, nil
		}
	} else if (ct == "text/plain" && m.plain == "") || (ct == "text/html" && m.html == "") {
		if reader, err := decodedBody(h, body); err == nil {
			if enc := params["charset"]; enc != "" {
				if converted, err := charset.NewReaderLabel(enc, reader); err == nil {
					reader = converted
				}
			}
			text, _ := io.ReadAll(io.LimitReader(reader, 16<<10))
			value := string(text)
			if ct == "text/html" {
				m.html = snippet(htmlText(value))
			} else {
				m.plain = snippet(value)
			}
		}
	}
	return raw, false, nil
}

func (m *message) parseMultipart(ctx context.Context, body []byte, boundary string, depth int) ([]byte, bool, error) {
	if boundary == "" || len(boundary) > 70 || strings.ContainsAny(boundary, "\r\n") {
		return nil, false, fmt.Errorf("invalid MIME multipart boundary")
	}
	delimiter := regexp.MustCompile(`(?m)^--` + regexp.QuoteMeta(boundary) + `(--)?[\t ]*(?:\r?\n|$)`)
	marks := delimiter.FindAllSubmatchIndex(body, 2002)
	if len(marks) < 2 {
		return nil, false, fmt.Errorf("incomplete MIME multipart")
	}
	kept := [][]byte{body[:marks[0][0]]}
	changed, count := false, 0
	for i, mark := range marks {
		if mark[2] >= 0 {
			if !changed {
				return body, false, nil
			}
			if count == 0 {
				kept = append(kept, []byte("--"+boundary+"\r\nContent-Type: text/plain\r\n\r\n\r\n"))
			}
			kept = append(kept, body[mark[0]:])
			return bytes.Join(kept, nil), true, nil
		}
		if i+1 == len(marks) {
			break
		}
		whole := body[mark[1]:marks[i+1][0]]
		part := bytes.TrimSuffix(whole, []byte("\n"))
		if len(part) < len(whole) {
			part = bytes.TrimSuffix(part, []byte("\r"))
		}
		processed, drop, err := m.parsePart(ctx, part, depth+1)
		if err != nil {
			return nil, false, err
		}
		if drop {
			changed = true
			continue
		}
		count++
		changed = changed || len(processed) != len(part) || !bytes.Equal(processed, part)
		kept = append(kept, body[mark[0]:mark[1]], processed, whole[len(part):])
	}
	return nil, false, fmt.Errorf("multipart exceeds the part limit or lacks a closing boundary")
}

func decodedBody(h textproto.MIMEHeader, raw []byte) (io.Reader, error) {
	r := bytes.NewReader(raw)
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
	case "", "binary", "7bit", "8bit":
		return r, nil
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r), nil
	case "quoted-printable":
		return quotedprintable.NewReader(r), nil
	default:
		return nil, fmt.Errorf("unsupported MIME transfer encoding")
	}
}

func snippet(s string) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > 280 {
		r = r[:280]
	}
	return string(r)
}

func htmlText(s string) string {
	z := html.NewTokenizer(strings.NewReader(s))
	var out strings.Builder
	hidden := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			return out.String()
		case html.StartTagToken:
			name, _ := z.TagName()
			if string(name) == "style" || string(name) == "script" {
				hidden = true
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if string(name) == "style" || string(name) == "script" {
				hidden = false
			}
		case html.TextToken:
			if !hidden {
				out.Write(z.Text())
				out.WriteByte(' ')
			}
		}
	}
}
