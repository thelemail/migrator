package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/thelemail/migrator/engine/internal/backup"
	"github.com/thelemail/migrator/engine/internal/destination"
	"github.com/thelemail/migrator/engine/internal/session"
	"github.com/thelemail/migrator/engine/internal/source"
)

type transferSource struct{ Kind, Server, Port, Security, Username, Password, Path, Directory string }

func (src transferSource) account() source.IMAPAccount {
	return source.IMAPAccount{Server: strings.TrimSpace(src.Server), Port: strings.TrimSpace(src.Port), Security: src.Security, Username: strings.TrimSpace(src.Username), Password: src.Password}
}

func (src transferSource) validate() error {
	switch src.Kind {
	case "imap":
		if strings.TrimSpace(src.Server) == "" || strings.TrimSpace(src.Username) == "" || src.Password == "" {
			return errors.New("enter the source IMAP server, email address and password")
		}
		switch src.Security {
		case "", source.SecurityTLS, source.SecurityStartTLS:
		default:
			return errors.New("choose SSL/TLS or STARTTLS")
		}
	case "files":
		if src.Path == "" {
			return errors.New("choose a mail file or folder")
		}
		info, err := os.Stat(src.Path)
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("choose a regular mail file or folder")
		}
	case "export":
		if strings.TrimSpace(src.Directory) == "" {
			return errors.New("choose an export folder")
		}
	default:
		return errors.New("unknown transfer type")
	}
	return nil
}

func stateDirectory() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(configDir, "Thelemail", "Migrator")
	return dir, os.MkdirAll(dir, 0700)
}

func runTransfer(ctx context.Context, s *session.Session, src transferSource, progress func(string)) error {
	if s == nil {
		return errors.New("sign in to Thelemail first")
	}
	if err := src.validate(); err != nil {
		return err
	}
	if err := rememberTransfer(s.AccountID, src); err != nil {
		return err
	}
	err := copyMail(ctx, s, src, progress)
	if err == nil {
		forgetTransfer(s.AccountID)
	}
	return err
}

func copyMail(ctx context.Context, s *session.Session, src transferSource, progress func(string)) error {
	if src.Kind == "export" {
		if err := backup.Run(ctx, s, src.Directory, func(folder string, count int) {
			progress(fmt.Sprintf("Exporting %s · %d messages written", folder, count))
		}); err != nil {
			return err
		}
		progress(fmt.Sprintf("Export complete · %s", src.Directory))
		return nil
	}
	if err := session.VerifyImport(ctx, s); err != nil {
		return err
	}
	imported, duplicates, skipped := 0, 0, 0
	fileSource := src.Kind == "files"
	var firstFailure, folderName string
	var lastUpdate time.Time
	summary := func() string {
		return fmt.Sprintf("%d copied · %d already present · %d skipped", imported, duplicates, skipped)
	}
	visit := func(name string, raw []byte, placement *destination.Placement, date time.Time, readErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if readErr == nil && placement != nil && fileSource {
			present, err := destination.Imported(ctx, s, [][]byte{placement.SourceKey})
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if present[string(placement.SourceKey)] {
				duplicates++
				return nil
			}
		}
		if readErr == nil {
			existing, err := destination.Import(ctx, s, raw, placement, date)
			if err != nil && !errors.Is(err, destination.ErrInvalidMessage) {
				return fmt.Errorf("%s: %w", name, err)
			}
			readErr = err
			if err == nil {
				if existing {
					duplicates++
				} else {
					imported++
				}
			}
		}
		if readErr != nil {
			skipped++
			if firstFailure == "" {
				firstFailure = fmt.Sprintf("%s: %v", name, readErr)
			}
			return source.ErrSkipped
		}
		if time.Since(lastUpdate) > 300*time.Millisecond {
			progress(folderName + summary())
			lastUpdate = time.Now()
		}
		return nil
	}
	var err error
	isDirectory := false
	if src.Kind == "files" {
		info, statErr := os.Stat(src.Path)
		if statErr != nil {
			return statErr
		}
		isDirectory = info.IsDir()
	}
	if src.Kind == "files" && !isDirectory {
		err = source.Files(ctx, src.Path, func(name string, raw []byte, readErr error) error {
			return visit(name, raw, nil, time.Time{}, readErr)
		})
	} else {
		key, keyErr := s.MigrationKey()
		if keyErr != nil {
			return keyErr
		}
		defer clear(key)
		stateDir, dirErr := stateDirectory()
		if dirErr != nil {
			return dirErr
		}
		lock := flock.New(filepath.Join(stateDir, fmt.Sprintf("%x.lock", source.Identity(key, "transfer"))))
		acquired, lockErr := lock.TryLock()
		if lockErr != nil {
			return lockErr
		}
		if !acquired {
			return errors.New("another folder import is running for this Thelemail account")
		}
		defer func() { _ = lock.Close() }()
		folders := destination.CollectionResolver(ctx, s, key, destination.KindFolder)
		labels := destination.CollectionResolver(ctx, s, key, destination.KindLabel)
		labelIDs := map[string]string{}
		labelID := func(l source.Label) (string, error) {
			k := strings.Join(l.Path, "\x00")
			if id, ok := labelIDs[k]; ok {
				return id, nil
			}
			id, err := labels(l.Path, l.Color)
			if err != nil {
				return "", err
			}
			labelIDs[k] = id
			return id, nil
		}
		open := func(folder source.Folder) (source.IMAPVisit, error) {
			folderName = folder.Name + " · "
			var id string
			if folder.Mailbox == "folder" {
				var err error
				id, err = folders(folder.Path, folder.Color)
				if err != nil {
					return nil, err
				}
			}
			return func(name string, raw []byte, info source.MessageInfo, readErr error) error {
				place := destination.Placement{Mailbox: folder.Mailbox, FolderID: id, Read: info.Read, Starred: info.Starred, SourceKey: info.SourceKey}
				for _, l := range info.Labels {
					lid, err := labelID(l)
					if err != nil {
						return fmt.Errorf("%s: %w", name, err)
					}
					place.LabelIDs = append(place.LabelIDs, lid)
				}
				return visit(name, raw, &place, info.Date, readErr)
			}, nil
		}
		known := func(keys [][]byte) (map[string]bool, error) { return destination.Imported(ctx, s, keys) }
		if isDirectory {
			err = source.FileMailbox(ctx, src.Path, key, open, progress)
		} else {
			account := src.account()
			progress("Connecting to the source mailbox…")
			var confirmed int
			confirmed, err = source.IMAP(ctx, account, s.AccountID, stateDir, key, open, known, progress)
			duplicates += confirmed
		}
	}
	if err != nil {
		return fmt.Errorf("%s. Transfer stopped: %w", summary(), err)
	}
	if skipped > 0 {
		return fmt.Errorf("%s. First skipped message: %s", summary(), firstFailure)
	}
	progress("Import complete · " + summary())
	return nil
}
