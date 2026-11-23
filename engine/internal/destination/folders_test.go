package destination

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/thelemail/migrator/engine/internal/session"
	"github.com/thelemail/trust/pgp"
)

func TestNestedFoldersUseExistingParentAndEncryptedNames(t *testing.T) {
	key, err := pgp.Generate("Owner", "owner@example.test", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	armor, err := key.ArmorPublic()
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := hex.DecodeString(key.Fingerprint())
	s := &session.Session{PublicKeyArmored: armor, Fingerprint: fp, AccountID: "owner", BaseURL: "https://fixture.test"}
	var created []createCollection
	var list []collection
	open := func(cipher []byte) (string, error) {
		opened, err := pgp.Decrypt([]*pgp.Key{key}, cipher, nil)
		if err != nil {
			return "", err
		}
		var meta struct {
			N string
			C *string
		}
		if err := json.Unmarshal(opened.Data, &meta); err != nil || (meta.C != nil && *meta.C != "#2f6b4f") {
			return "", errors.New("invalid folder metadata")
		}
		return meta.N, nil
	}
	sealed, err := pgp.Encrypt([]byte(`{"n":"Clients","c":null}`), []*pgp.Key{key}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	list = append(list, collection{Kind: "folder", ID: "existing", Sealed: sealed})
	c := client{s, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/mail/collections" {
			t.Fatalf("unexpected URL %s", r.URL.Path)
		}
		var out any
		switch r.Method {
		case http.MethodGet:
			out = map[string][]collection{"collections": list}
		case http.MethodPost:
			var create createCollection
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body, &create); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(body, []byte("Azul")) || create.Kind != "folder" || create.Version != 2 || !bytes.Equal(create.Fingerprint, fp) || len(create.Key) != 32 {
				t.Fatal("invalid folder wire metadata")
			}
			name, err := open(create.Sealed)
			if err != nil || name != "Azul" {
				t.Fatalf("could not open folder name: %s %v", name, err)
			}
			created = append(created, create)
			item := collection{Kind: "folder", ID: fmt.Sprint(len(created)), Parent: create.Parent, Sealed: create.Sealed, Position: create.Position}
			list = append(list, item)
			out = item
		default:
			t.Fatal(r.Method)
		}
		b, _ := json.Marshal(out)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b))}, nil
	}}
	for i := 0; i < 2; i++ {
		tree, err := readFolders(t.Context(), c, KindFolder, open)
		if err != nil {
			t.Fatal(err)
		}
		id, err := tree.ensure(t.Context(), c, []byte("test namespace"), []string{"Clients", "Azul"}, "#2f6b4f")
		if err != nil || id != "1" || len(created) != 1 || created[0].Parent != "existing" {
			t.Fatalf("id=%s created=%d err=%v", id, len(created), err)
		}
	}
	labels, err := readFolders(t.Context(), c, KindLabel, open)
	if err != nil || len(labels.ids) != 0 {
		t.Fatalf("folders leaked into the label tree: %v %v", labels, err)
	}
}
