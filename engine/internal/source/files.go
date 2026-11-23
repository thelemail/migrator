package source

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const MaxMessageBytes = 50 << 20

var ErrSkipped = errors.New("message skipped")

var ErrTooLarge = errors.New("message exceeds the 50 MiB import limit")

type Visit func(name string, raw []byte, sourceErr error) error

func Files(ctx context.Context, path string, visit Visit) error {
	path = filepath.Clean(path)
	visitFile := func(name string, raw []byte, err error) error {
		result := visit(name, raw, err)
		if errors.Is(result, ErrSkipped) {
			return nil
		}
		return result
	}
	found := false
	err := filepath.WalkDir(path, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(name))
		if !entry.Type().IsRegular() || (ext != ".eml" && ext != ".mbox") {
			return nil
		}
		found = true
		return readMailFile(ctx, name, visitFile)
	})
	if err == nil && !found {
		return errors.New("choose an .eml or .mbox file, or a folder containing them")
	}
	return err
}

func readMailFile(ctx context.Context, name string, visit Visit) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if strings.EqualFold(filepath.Ext(name), ".mbox") {
		return readMbox(ctx, file, name, visit)
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxMessageBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > MaxMessageBytes {
		return visit(name, nil, ErrTooLarge)
	}
	return visit(name, raw, nil)
}

func readMbox(ctx context.Context, input io.Reader, name string, visit Visit) error {
	reader := bufio.NewReaderSize(input, 64<<10)
	var message bytes.Buffer
	index := 0
	oversize := false
	finish := func() error {
		if index == 0 {
			return nil
		}
		label := fmt.Sprintf("%s (message %d)", name, index)
		if oversize {
			return visit(label, nil, ErrTooLarge)
		}
		raw := message.Bytes()
		if bytes.HasSuffix(raw, []byte("\r\n\r\n")) {
			raw = raw[:len(raw)-2]
		} else if bytes.HasSuffix(raw, []byte("\n\n")) {
			raw = raw[:len(raw)-1]
		}
		if len(raw) > MaxMessageBytes {
			return visit(label, nil, ErrTooLarge)
		}
		return visit(label, raw, nil)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := reader.ReadSlice('\n')
		long := errors.Is(err, bufio.ErrBufferFull)
		if err != nil && err != io.EOF && !long {
			return err
		}
		if len(line) == 0 && err == io.EOF {
			return finish()
		}
		envelope := bytes.HasPrefix(line, []byte("From "))
		if envelope {
			if err := finish(); err != nil {
				return err
			}
			index++
			message.Reset()
			oversize = false
		} else if index == 0 {
			if long || len(bytes.TrimSpace(line)) != 0 {
				return fmt.Errorf("%s is missing an MBOX envelope", name)
			}
		} else if len(line) > 0 && line[0] == '>' && bytes.HasPrefix(bytes.TrimLeft(line, ">"), []byte("From ")) {
			line = line[1:]
		}

		for {
			if index > 0 && !envelope && !oversize {
				if len(line) > MaxMessageBytes+2-message.Len() {
					oversize = true
				} else {
					message.Write(line)
				}
			}
			if !long {
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			line, err = reader.ReadSlice('\n')
			long = errors.Is(err, bufio.ErrBufferFull)
			if err != nil && err != io.EOF && !long {
				return err
			}
		}
		if err == io.EOF {
			return finish()
		}
	}
}
