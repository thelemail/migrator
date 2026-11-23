package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/mail"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type fileGroup struct {
	folder Folder
	files  []string
}

type backupEntry struct {
	ID     string `json:"id"`
	Parent string `json:"parentId"`
	Name   string `json:"name"`
	Color  string `json:"color"`
	File   string `json:"file"`
}

type backupMessage struct {
	MessageIDHeader string   `json:"messageIdHeader"`
	LabelIDs        []string `json:"labelIds"`
}

type backupManifest struct {
	folders map[string]Folder
	labels  map[string][]Label
}

func readBackup(dir string) (*backupManifest, error) {
	path := filepath.Join(dir, "organization.json")
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) || err == nil && !st.Mode().IsRegular() {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var org struct {
		Folders  []backupEntry   `json:"folders"`
		Labels   []backupEntry   `json:"labels"`
		Messages []backupMessage `json:"messages"`
	}
	if err := json.Unmarshal(raw, &org); err != nil {
		return nil, errors.New("organization.json must contain a JSON object")
	}
	if org.Folders == nil {
		return nil, nil
	}
	folders, err := backupFolders(org.Folders)
	if err != nil {
		return nil, err
	}
	labels, err := backupLabels(org.Labels, org.Messages)
	if err != nil {
		return nil, err
	}
	return &backupManifest{folders: folders, labels: labels}, nil
}

func entryPaths(entries []backupEntry, kind string) (map[string][]string, map[string]backupEntry, error) {
	byID := make(map[string]backupEntry, len(entries))
	for _, e := range entries {
		if e.ID == "" || byID[e.ID].ID != "" {
			return nil, nil, fmt.Errorf("organization.json contains an invalid %s ID", kind)
		}
		byID[e.ID] = e
	}
	paths := make(map[string][]string, len(entries))
	for _, e := range entries {
		var parts []string
		for cur := e; ; {
			name := cur.Name
			if name == "" {
				name = cur.ID
			}
			parts = append(parts, name)
			if len(parts) > len(entries) {
				return nil, nil, fmt.Errorf("organization.json contains a %s cycle", kind)
			}
			if cur.Parent == "" {
				break
			}
			parent, ok := byID[cur.Parent]
			if !ok {
				return nil, nil, fmt.Errorf("organization.json is missing the parent of %q", name)
			}
			cur = parent
		}
		slices.Reverse(parts)
		paths[e.ID] = parts
	}
	return paths, byID, nil
}

func backupFolders(entries []backupEntry) (map[string]Folder, error) {
	for _, e := range entries {
		if !filepath.IsLocal(e.File) || filepath.Base(e.File) != e.File || e.File == "." {
			return nil, errors.New("organization.json contains an invalid folder ID or MBOX filename")
		}
	}
	paths, _, err := entryPaths(entries, "folder")
	if err != nil {
		return nil, err
	}
	folders := make(map[string]Folder, len(entries))
	siblings := map[[2]string]bool{}
	for _, e := range entries {
		parts := paths[e.ID]
		name := e.File + ".mbox"
		sibling := [2]string{e.Parent, parts[len(parts)-1]}
		if _, dup := folders[name]; dup || siblings[sibling] {
			return nil, fmt.Errorf("organization.json has ambiguous folder names or filenames for %q", name)
		}
		siblings[sibling] = true
		folders[name] = Folder{Name: strings.Join(parts, " / "), Mailbox: "folder", Path: parts, Color: e.Color}
	}
	return folders, nil
}

func backupLabels(entries []backupEntry, messages []backupMessage) (map[string][]Label, error) {
	paths, byID, err := entryPaths(entries, "label")
	if err != nil {
		return nil, err
	}
	out := map[string][]Label{}
	for _, m := range messages {
		id := normalizeMessageID(m.MessageIDHeader)
		if id == "" {
			continue
		}
		for _, labelID := range m.LabelIDs {
			if path, ok := paths[labelID]; ok && !slices.ContainsFunc(out[id], func(l Label) bool { return slices.Equal(l.Path, path) }) {
				out[id] = append(out[id], Label{Path: path, Color: byID[labelID].Color})
			}
		}
	}
	return out, nil
}

func normalizeMessageID(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func diskFolder(parts []string) Folder {
	f := Folder{Name: strings.Join(parts, " / "), Path: parts, Mailbox: "folder"}
	if len(parts) == 0 {
		return Folder{Name: "Inbox", Mailbox: "inbox"}
	}
	if len(parts) == 1 {
		switch strings.ToLower(parts[0]) {
		case "inbox":
			f.Mailbox = "inbox"
		case "sent", "sent mail", "sent items", "sent messages":
			f.Mailbox = "sent"
		case "archive", "archives":
			f.Mailbox = "archive"
		case "spam", "junk", "junk e-mail", "junk email":
			f.Mailbox = "spam"
		case "trash", "deleted messages", "deleted items":
			f.Mailbox = "trash"
		}
	}
	return f
}

func fileGroups(ctx context.Context, dir string) ([]*fileGroup, string, map[string][]Label, error) {
	backup, err := readBackup(dir)
	if err != nil {
		return nil, "", nil, err
	}
	var manifest map[string]Folder
	var labels map[string][]Label
	if backup != nil {
		manifest, labels = backup.folders, backup.labels
	}
	var groups []*fileGroup
	byFolder := map[string]*fileGroup{}
	add := func(f Folder, file string) {
		parts := []string{f.Mailbox}
		if f.Mailbox == "folder" {
			parts = append(parts, f.Path...)
		}
		id, _ := json.Marshal(parts)
		g := byFolder[string(id)]
		if g == nil {
			g = &fileGroup{folder: f}
			byFolder[string(id)] = g
			groups = append(groups, g)
		}
		if file != "" {
			g.files = append(g.files, file)
		}
	}
	var stars string
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == dir {
			if !entry.IsDir() {
				return errors.New("select a directory of EML or MBOX files")
			}
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if entry.IsDir() {
			if manifest != nil && rel == "private-keys" {
				return fs.SkipDir
			}
			add(diskFolder(parts), "")
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		ext := filepath.Ext(entry.Name())
		switch strings.ToLower(ext) {
		case ".eml":
			add(diskFolder(parts[:len(parts)-1]), path)
		case ".mbox":
			if f, ok := manifest[rel]; ok {
				add(f, path)
				delete(manifest, rel)
			} else if manifest != nil && rel == "starred.mbox" {
				stars = path
			} else {
				parts[len(parts)-1] = strings.TrimSuffix(entry.Name(), ext)
				add(diskFolder(parts), path)
			}
		}
		return nil
	})
	if err == nil {
		for file := range manifest {
			return nil, "", nil, fmt.Errorf("organization.json refers to a missing MBOX: %s", file)
		}
	}
	return groups, stars, labels, err
}

func fileMessageInfo(raw []byte, labels map[string][]Label) MessageInfo {
	info := MessageInfo{Read: true}
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err == nil {
		info.Labels = labels[normalizeMessageID(message.Header.Get("Message-Id"))]
		if status, present := message.Header["Status"]; present {
			info.Read = strings.Contains(strings.ToUpper(strings.Join(status, "")), "R")
		}
		info.Starred = strings.Contains(strings.ToUpper(message.Header.Get("X-Status")), "F")
		info.Date, _ = message.Header.Date()
	}
	return info
}

func FileMailbox(ctx context.Context, path string, key []byte, open OpenFolder, progress func(string)) error {
	groups, stars, labels, err := fileGroups(ctx, filepath.Clean(path))
	if err != nil {
		return err
	}
	if len(groups) == 0 && stars == "" {
		return errors.New("the directory contains no mail files or folders")
	}
	type digest = [sha256.Size]byte
	starred := map[digest]int{}
	matched := map[digest]int{}
	if stars != "" {
		progress("Checking starred messages…")
		if err := readMailFile(ctx, stars, func(_ string, raw []byte, readErr error) error {
			if readErr == nil {
				starred[sha256.Sum256(raw)]++
			}
			return nil
		}); err != nil {
			return err
		}
		groups = append(groups, &fileGroup{folder: Folder{Name: "Starred", Mailbox: "folder", Path: []string{"Starred"}}, files: []string{stars}})
	}
	for _, g := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		isStarView := stars != "" && len(g.files) == 1 && g.files[0] == stars
		var visit IMAPVisit
		begin := func() error {
			progress(g.folder.Name)
			var err error
			visit, err = open(g.folder)
			return err
		}
		if !isStarView {
			if err := begin(); err != nil {
				return err
			}
		}
		occurrences := map[digest]int{}
		for _, file := range g.files {
			err := readMailFile(ctx, file, func(name string, raw []byte, readErr error) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				sum := sha256.Sum256(raw)
				if isStarView && readErr == nil && matched[sum] > 0 {
					matched[sum]--
					return nil
				}
				if visit == nil {
					if err := begin(); err != nil {
						return err
					}
				}
				info := fileMessageInfo(raw, labels)
				occurrences[sum]++
				parts := []string{"file-message/v1", g.folder.Mailbox}
				if g.folder.Mailbox == "folder" {
					parts = append(parts, g.folder.Path...)
				}
				if isStarView {
					parts[0] = "file-starred-view/v1"
				}
				parts = append(parts, hex.EncodeToString(sum[:]), strconv.Itoa(occurrences[sum]))
				info.SourceKey = Identity(key, parts...)
				info.Starred = info.Starred || isStarView || starred[sum] > 0
				err := visit(name, raw, info, readErr)
				if errors.Is(err, ErrSkipped) {
					return nil
				}
				if err == nil && readErr == nil && !isStarView && starred[sum] > 0 {
					starred[sum]--
					matched[sum]++
				}
				return err
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}
