package destination

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/thelemail/migrator/engine/internal/session"
	"github.com/thelemail/migrator/engine/internal/source"
	"github.com/thelemail/trust/pgp"
)

const (
	KindFolder = "folder"
	KindLabel  = "label"
)

type folderName struct{ parent, name string }

type folders struct {
	kind string
	ids  map[folderName]string
	last map[string]int64
}

type collection struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Parent   string `json:"parentId"`
	Position int64  `json:"position"`
	Deleted  bool   `json:"deleted"`
	Sealed   []byte `json:"sealedMeta"`
}

type createCollection struct {
	Kind        string `json:"kind"`
	Parent      string `json:"parentId,omitempty"`
	Position    int64  `json:"position"`
	Sealed      []byte `json:"sealedMeta"`
	Fingerprint []byte `json:"metaKeyFingerprint"`
	Version     int    `json:"metaSchemaVersion"`
	Key         []byte `json:"creationKey"`
}

func readFolders(ctx context.Context, c client, kind string, decrypt func([]byte) (string, error)) (*folders, error) {
	var list struct {
		Collections []collection `json:"collections"`
	}
	if err := c.request(ctx, http.MethodGet, "/v1/mail/collections", "", nil, &list); err != nil {
		return nil, err
	}
	if list.Collections == nil {
		return nil, errors.New("destination did not return its folder list")
	}
	tree := &folders{kind: kind, ids: map[folderName]string{}, last: map[string]int64{}}
	for _, item := range list.Collections {
		if item.Kind != kind || item.Deleted {
			continue
		}
		tree.last[item.Parent] = max(tree.last[item.Parent], item.Position)
		name, err := decrypt(item.Sealed)
		if err != nil {
			continue
		}
		k := folderName{item.Parent, name}
		if _, duplicate := tree.ids[k]; duplicate {
			tree.ids[k] = ""
		} else {
			tree.ids[k] = item.ID
		}
	}
	return tree, nil
}

func (tree *folders) ensure(ctx context.Context, c client, key []byte, path []string, color string) (string, error) {
	parent := ""
	for i, name := range path {
		if strings.TrimSpace(name) == "" {
			return "", fmt.Errorf("the source has a %s with an empty name", tree.kind)
		}
		k := folderName{parent, name}
		if id, found := tree.ids[k]; found {
			if id == "" {
				return "", fmt.Errorf("two destination %ss are named %q under the same parent; rename one and retry", tree.kind, name)
			}
			parent = id
			continue
		}
		var tint *string
		if i == len(path)-1 && color != "" {
			tint = &color
		}
		plain, err := json.Marshal(map[string]any{"n": name, "c": tint})
		if err != nil {
			return "", err
		}
		pub, err := pgp.ParseKey(c.PublicKeyArmored)
		if err != nil {
			return "", err
		}
		sealed, err := pgp.Encrypt(plain, []*pgp.Key{pub}, nil, false)
		if err != nil {
			return "", err
		}
		creationKey := source.Identity(key, append([]string{tree.kind}, path[:i+1]...)...)
		create := createCollection{tree.kind, parent, tree.last[parent] + 1024, sealed, c.Fingerprint, 2, creationKey}
		var item collection
		if err := c.post(ctx, "/v1/mail/collections", create, &item); err != nil {
			return "", fmt.Errorf("create %s %q: %w", tree.kind, name, err)
		}
		if item.ID == "" || item.Kind != tree.kind || item.Deleted || item.Parent != parent {
			return "", fmt.Errorf("destination did not confirm the %s and its parent", tree.kind)
		}
		tree.ids[k] = item.ID
		tree.last[parent] = max(item.Position, tree.last[parent])
		parent = item.ID
	}
	return parent, nil
}

type Resolver func(path []string, color string) (string, error)

func CollectionResolver(ctx context.Context, s *session.Session, key []byte, kind string) Resolver {
	c := client{s, s.Do}
	var tree *folders
	return func(path []string, color string) (string, error) {
		if tree == nil {
			var err error
			tree, err = readFolders(ctx, c, kind, s.OpenFolderName)
			if err != nil {
				return "", err
			}
		}
		return tree.ensure(ctx, c, key, path, color)
	}
}
