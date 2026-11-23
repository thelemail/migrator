package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/thelemail/export-tool/transfer"
)

const (
	testAuth    = "https://auth.thelemail.test"
	testAccount = "ada@thelemail.test"

	passkeyCodeVector = "AKTC-EUFO"
)

func testPage(shown func(string)) passkeyPage {
	return passkeyPage{auth: testAuth, account: testAccount, shown: shown}
}

type handBack struct {
	port, state, account string
	options              []byte
}

func openedPage(t *testing.T, opened string) handBack {
	t.Helper()
	u, err := url.Parse(opened)
	if err != nil || u.Scheme+"://"+u.Host != testAuth || u.Path != "/migrator/passkey" || u.RawQuery != "" {
		t.Fatalf("opened %q", opened)
	}
	_, fragment, _ := strings.Cut(opened, "#")
	if !strings.Contains(fragment, "account=ada%40thelemail.test") || strings.Contains(fragment, "%25") {
		t.Fatalf("fragment %q is not escaped exactly once", fragment)
	}
	parts, err := url.ParseQuery(fragment)
	if err != nil {
		t.Fatalf("fragment %q: %v", fragment, err)
	}
	options, err := base64.RawURLEncoding.DecodeString(parts.Get("options"))
	if err != nil {
		t.Fatal(err)
	}
	return handBack{parts.Get("port"), parts.Get("state"), parts.Get("account"), options}
}

func (h handBack) visit(t *testing.T, host string, query url.Values) (int, string) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+h.port+"/migrator/passkey/result?"+query.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

func TestPasskeyHandBackIsSingleUseAndBoundToItsState(t *testing.T) {
	options := json.RawMessage(`{"challenge":"Y2g","rpId":"thelemail.test"}`)
	credential := `{"type":"public-key","id":"fixture"}`
	shown := ""
	got, err := requestPasskey(t.Context(), transfer.PasskeyRequest{Options: options, Expires: time.Now().Add(time.Minute)}, testPage(func(code string) { shown = code }), func(ctx context.Context, opened string) error {
		page := openedPage(t, opened)
		if string(page.options) != string(options) || len(page.state) != 43 || page.account != testAccount {
			t.Fatalf("page got options %s state %q account %q", page.options, page.state, page.account)
		}
		if shown == "" || shown != PasskeyCode(page.state) {
			t.Fatalf("Migrator showed %q before the browser opened, want %q", shown, PasskeyCode(page.state))
		}
		encoded := base64.RawURLEncoding.EncodeToString([]byte(credential))
		if code, _ := page.visit(t, "evil.test:"+page.port, url.Values{"state": {page.state}, "credential": {encoded}}); code != http.StatusNotFound {
			t.Fatalf("rebound host answered %d", code)
		}
		if code, loc := page.visit(t, "", url.Values{"state": {"wrong"}, "credential": {encoded}}); code != http.StatusSeeOther || loc != testAuth+"/migrator/passkey#done=failed" {
			t.Fatalf("wrong state: %d %s", code, loc)
		}
		if code, loc := page.visit(t, "", url.Values{"state": {page.state}, "credential": {"bm90IGpzb24"}}); code != http.StatusSeeOther || !strings.HasSuffix(loc, "#done=failed") {
			t.Fatalf("malformed credential: %d %s", code, loc)
		}
		if code, loc := page.visit(t, "", url.Values{"state": {page.state}, "credential": {encoded}}); code != http.StatusSeeOther || loc != testAuth+"/migrator/passkey#done=ok" {
			t.Fatalf("hand back: %d %s", code, loc)
		}
		if code, loc := page.visit(t, "", url.Values{"state": {page.state}, "credential": {encoded}}); code != http.StatusSeeOther || !strings.HasSuffix(loc, "#done=failed") {
			t.Fatalf("replay: %d %s", code, loc)
		}
		return nil
	})
	if err != nil || string(got) != credential {
		t.Fatalf("got %s, %v", got, err)
	}
}

func TestPasskeyCancelFromTheBrowser(t *testing.T) {
	_, err := requestPasskey(t.Context(), transfer.PasskeyRequest{Options: json.RawMessage(`{}`)}, testPage(nil), func(ctx context.Context, opened string) error {
		page := openedPage(t, opened)
		if code, loc := page.visit(t, "", url.Values{"state": {page.state}, "cancel": {"1"}}); code != http.StatusSeeOther || !strings.HasSuffix(loc, "#done=cancelled") {
			t.Fatalf("cancel: %d %s", code, loc)
		}
		return nil
	})
	if !errors.Is(err, ErrPasskeyCancelled) {
		t.Fatalf("err = %v", err)
	}
}

func TestPasskeyWaitEndsWithThePendingToken(t *testing.T) {
	start := time.Now()
	_, err := requestPasskey(t.Context(), transfer.PasskeyRequest{Options: json.RawMessage(`{}`), Expires: time.Now().Add(150 * time.Millisecond)}, testPage(nil), func(context.Context, string) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
}

func TestPasskeyCodeMatchesTheBrowserDerivation(t *testing.T) {
	if got := PasskeyCode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); got != passkeyCodeVector {
		t.Fatalf("PasskeyCode = %q, want %q", got, passkeyCodeVector)
	}
	if PasskeyCode("a") == PasskeyCode("b") {
		t.Fatal("different states gave the same code")
	}
}
