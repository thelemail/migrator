package destination

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/thelemail/migrator/engine/internal/session"
)

type lookupTransport struct {
	t       *testing.T
	known   map[string]bool
	batches []int
}

func (l *lookupTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path != "/v1/messages/import/lookup" || r.Method != http.MethodPost {
		l.t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
	}
	var in struct {
		SourceKeys [][]byte `json:"sourceKeys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		l.t.Fatal(err)
	}
	l.batches = append(l.batches, len(in.SourceKeys))
	out := struct {
		Existing [][]byte `json:"existing"`
	}{Existing: [][]byte{}}
	for _, k := range in.SourceKeys {
		if l.known[string(k)] {
			out.Existing = append(out.Existing, k)
		}
	}
	b, _ := json.Marshal(out)
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(b)), Header: http.Header{}}, nil
}

func TestImportedChecksSourceKeysInBatches(t *testing.T) {
	keys := make([][]byte, 0, 1201)
	for i := range 1201 {
		keys = append(keys, bytes.Repeat([]byte{byte(i % 251)}, 31))
		keys[i] = append(keys[i], byte(i/251))
	}
	transport := &lookupTransport{t: t, known: map[string]bool{string(keys[7]): true, string(keys[1200]): true}}
	s := &session.Session{BaseURL: "https://api.example.test"}
	c := client{s, (&http.Client{Transport: transport}).Do}
	known, err := c.imported(t.Context(), keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(known) != 2 || !known[string(keys[7])] || !known[string(keys[1200])] {
		t.Fatalf("known = %d", len(known))
	}
	if len(transport.batches) != 3 || transport.batches[0] != 500 || transport.batches[2] != 201 {
		t.Fatalf("batches = %v", transport.batches)
	}
}
