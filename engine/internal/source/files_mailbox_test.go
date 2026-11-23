package source

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeMailFile(t *testing.T, dir, path, text string) {
	t.Helper()
	target := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

type importedFolder struct {
	folder Folder
	infos  []MessageInfo
}

func collectMailFiles(t *testing.T, dir string) map[string]*importedFolder {
	t.Helper()
	out := map[string]*importedFolder{}
	err := FileMailbox(t.Context(), dir, []byte("private key"), func(f Folder) (IMAPVisit, error) {
		id := f.Mailbox
		if id == "folder" {
			id += ":" + strings.Join(f.Path, "|")
		}
		entry := &importedFolder{folder: f}
		out[id] = entry
		return func(_ string, _ []byte, info MessageInfo, err error) error {
			entry.infos = append(entry.infos, info)
			return err
		}, nil
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDirectoryMailboxes(t *testing.T) {
	dir := t.TempDir()
	mail := "Subject: Old mail\nDate: Sat, 31 Jan 2015 10:00:00 +0000\nStatus: O\nX-Status: F\n\nbody\n"
	mbox := "From a Sat Jan 31 10:00:00 2015\n" + mail + "\n"
	writeMailFile(t, dir, "a.eml", mail)
	writeMailFile(t, dir, "Inbox.MBOX", mbox)
	writeMailFile(t, dir, "Sent Items/letter.eml", mail)
	writeMailFile(t, dir, "Clients/Acme.mbox", mbox+mbox)
	writeMailFile(t, dir, "Clients/Notes/letter.eml", "Subject: Note\n\nNo status")
	if err := os.Mkdir(filepath.Join(dir, "Empty"), 0700); err != nil {
		t.Fatal(err)
	}
	out := collectMailFiles(t, dir)
	inbox := out["inbox"].infos
	if len(inbox) != 2 || inbox[0].Read || !inbox[0].Starred || inbox[0].Date.Year() != 2015 {
		t.Fatalf("lost Inbox messages or source flags/date: %+v", inbox)
	}
	if len(out["folder:Empty"].infos) != 0 || len(out["folder:Clients"].infos) != 0 ||
		len(out["folder:Clients|Acme"].infos) != 2 || !out["folder:Clients|Notes"].infos[0].Read || len(out["sent"].infos) != 1 {
		t.Fatalf("incorrect directory placement: %+v", out)
	}
	ids := map[string]bool{}
	for _, f := range out {
		for _, m := range f.infos {
			if len(m.SourceKey) != 32 || ids[string(m.SourceKey)] {
				t.Fatal("source identities collided")
			}
			ids[string(m.SourceKey)] = true
		}
	}
	if err := os.Rename(filepath.Join(dir, "a.eml"), filepath.Join(dir, "b.eml")); err != nil {
		t.Fatal(err)
	}
	again := collectMailFiles(t, dir)
	for id, f := range out {
		for i, msg := range f.infos {
			if !bytes.Equal(again[id].infos[i].SourceKey, msg.SourceKey) {
				t.Fatal("keys depend on a filename")
			}
		}
	}
}

func TestBackupFolderTreeAndStarredView(t *testing.T) {
	dir := t.TempDir()
	writeMailFile(t, dir, "organization.json", `{"labels":[],"folders":[{"id":"p","name":"Clients / Sales","file":"folder sales"},{"id":"c","name":"Acme","file":"folder acme","parentId":"p"}],"messages":[]}`)
	entry := func(s string) string {
		return fmt.Sprintf("From a Sat Jan 31 10:00:00 2015\nSubject: %s\n\nbody\n\n", s)
	}
	writeMailFile(t, dir, "folder sales.mbox", "")
	writeMailFile(t, dir, "private-keys/key.asc", "not a mail folder")
	writeMailFile(t, dir, "folder acme.mbox", entry("starred"))
	writeMailFile(t, dir, "starred.mbox", entry("starred")+entry("only in the starred view"))
	out := collectMailFiles(t, dir)
	child := out["folder:Clients / Sales|Acme"]
	if !slices.Equal(child.folder.Path, []string{"Clients / Sales", "Acme"}) || len(child.infos) != 1 || !child.infos[0].Starred {
		t.Fatal("lost original folder hierarchy or star")
	}
	if out["folder:Clients / Sales"] == nil || len(out["folder:Starred"].infos) != 1 || !out["folder:Starred"].infos[0].Starred {
		t.Fatal("lost empty parent or unique starred message")
	}
	writeMailFile(t, dir, "starred.mbox", entry("starred"))
	out = collectMailFiles(t, dir)
	if out["folder:Starred"] != nil || out["folder:private-keys"] != nil {
		t.Fatal("duplicated a redundant starred view")
	}
}

func TestMissingBackupFileStopsBeforePlacement(t *testing.T) {
	dir := t.TempDir()
	writeMailFile(t, dir, "organization.json", `{"folders":[{"id":"f","file":"missing"}]}`)
	writeMailFile(t, dir, "a.eml", "Subject: a\n\nb")
	opened := false
	err := FileMailbox(t.Context(), dir, nil, func(Folder) (IMAPVisit, error) {
		opened = true
		return nil, errors.New("unexpected")
	}, func(string) {})
	if opened || err == nil || !strings.Contains(err.Error(), "missing MBOX") {
		t.Fatalf("opened = %t, err = %v", opened, err)
	}
}

func TestBackupRestoresLabelsAndColors(t *testing.T) {
	dir := t.TempDir()
	writeMailFile(t, dir, "organization.json", `{
  "folders": [{"id":"f","name":"Clients","color":"#2f6b4f","file":"folder clients"}],
  "labels": [{"id":"w","name":"Work","color":"#a33"},{"id":"u","name":"Urgent","parentId":"w"}],
  "messages": [
    {"id":"1","messageIdHeader":"<One@Example.test>","labelIds":["u","w","gone"]},
    {"id":"2","labelIds":["w"]}
  ]
}`)
	entry := func(id, subject string) string {
		return fmt.Sprintf("From a Sat Jan 31 10:00:00 2015\nMessage-ID: %s\nSubject: %s\n\nbody\n\n", id, subject)
	}
	writeMailFile(t, dir, "folder clients.mbox", entry("<one@example.test>", "labelled")+entry("<two@example.test>", "plain"))
	out := collectMailFiles(t, dir)
	clients := out["folder:Clients"]
	if clients == nil || clients.folder.Color != "#2f6b4f" || len(clients.infos) != 2 {
		t.Fatalf("folder = %+v", clients)
	}
	labels := clients.infos[0].Labels
	if len(labels) != 2 || !slices.Equal(labels[0].Path, []string{"Work", "Urgent"}) || !slices.Equal(labels[1].Path, []string{"Work"}) || labels[1].Color != "#a33" {
		t.Fatalf("labels = %+v", labels)
	}
	if len(clients.infos[1].Labels) != 0 {
		t.Fatalf("unlabelled message got %+v", clients.infos[1].Labels)
	}
}
