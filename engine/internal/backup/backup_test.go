package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClaimDirectoryKeepsMailboxesSeparate(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "inbox.mbox"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := claimDirectory(out, "first"); err == nil {
		t.Fatal("claimed unrelated files")
	}
	owned := filepath.Join(out, "backup")
	if err := claimDirectory(owned, "first"); err != nil {
		t.Fatal(err)
	}
	if err := claimDirectory(owned, "first"); err != nil {
		t.Fatal(err)
	}
	if err := claimDirectory(owned, "second"); err == nil {
		t.Fatal("claimed another mailbox's export")
	}
}
