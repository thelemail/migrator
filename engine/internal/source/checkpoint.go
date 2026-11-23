package source

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/emersion/go-imap/v2"
)

type checkpoint struct {
	path   string
	copied imap.UIDSet
	dirty  int
}

func loadCheckpoint(directory, destination, server, username, folder string, validity uint32) (*checkpoint, error) {
	cp := &checkpoint{}
	if validity == 0 {
		return cp, nil
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	identity, err := json.Marshal([]string{destination, server, username, folder, strconv.FormatUint(uint64(validity), 10)})
	if err != nil {
		return nil, err
	}
	cp.path = filepath.Join(directory, fmt.Sprintf("%x.json", sha256.Sum256(identity)))
	data, err := os.ReadFile(cp.path)
	if errors.Is(err, os.ErrNotExist) {
		return cp, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &cp.copied); err != nil {
		return nil, fmt.Errorf("read transfer checkpoint: %w", err)
	}
	return cp, nil
}

func (cp *checkpoint) save() error {
	if cp.path == "" || cp.dirty == 0 {
		return nil
	}
	file, err := os.CreateTemp(filepath.Dir(cp.path), ".checkpoint-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if err := json.NewEncoder(file).Encode(cp.copied); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), cp.path); err != nil {
		return err
	}
	cp.dirty = 0
	return nil
}
