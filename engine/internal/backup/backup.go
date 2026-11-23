package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofrs/flock"
	"github.com/thelemail/export-tool/transfer"
	"github.com/thelemail/migrator/engine/internal/session"
)

const markerName = ".thelemail-migrator"

func Run(ctx context.Context, s *session.Session, out string, progress func(folder string, messages int)) error {
	if err := claimDirectory(out, s.AccountID); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(out, markerName))
	ok, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("another export is already writing to this folder")
	}
	defer func() { _ = lock.Close() }()
	err = s.Export(ctx, out, io.Discard, progress)
	if errors.Is(err, transfer.ErrIncomplete) {
		return fmt.Errorf("%w; see export-report.json in the output folder", err)
	}
	return err
}

func claimDirectory(dir, account string) error {
	if strings.TrimSpace(dir) == "" || account == "" {
		return errors.New("choose an output folder and sign in first")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	marker := filepath.Join(dir, markerName)
	raw, err := os.ReadFile(marker)
	if err == nil {
		if string(raw) != account {
			return errors.New("this folder contains another mailbox's export")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() != ".DS_Store" && e.Name() != "desktop.ini" {
			return errors.New("choose an empty folder, or reopen this mailbox's previous Migrator export")
		}
	}
	f, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(account); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
