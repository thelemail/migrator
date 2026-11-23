package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

type resumable struct {
	Kind      string `json:"kind"`
	Server    string `json:"server,omitempty"`
	Port      string `json:"port,omitempty"`
	Security  string `json:"security,omitempty"`
	Path      string `json:"path,omitempty"`
	Directory string `json:"directory,omitempty"`
}

func resumePath(account string) (string, error) {
	dir, err := stateDirectory()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte("resume/v1/" + account))
	return filepath.Join(dir, "resume-"+hex.EncodeToString(sum[:8])+".json"), nil
}

func rememberTransfer(account string, src transferSource) error {
	path, err := resumePath(account)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(resumable{Kind: src.Kind, Server: src.Server, Port: src.Port, Security: src.Security, Path: src.Path, Directory: src.Directory})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func forgetTransfer(account string) {
	if path, err := resumePath(account); err == nil {
		_ = os.Remove(path)
	}
}

func lastTransfer(account string) (*resumable, error) {
	path, err := resumePath(account)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var last resumable
	if err := json.Unmarshal(raw, &last); err != nil || last.Kind == "" {
		_ = os.Remove(path)
		return nil, nil
	}
	return &last, nil
}
