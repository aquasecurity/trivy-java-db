package utils

import (
	"encoding/json"
	"golang.org/x/xerrors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

func FileWalk(root string, walkFn func(r io.Reader, path string) error) error {
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return xerrors.Errorf("file info error: %w", err)
		}

		if info.Size() == 0 {
			log.Printf("invalid size: %s\n", path)
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("failed to open file: %w", err)
		}
		defer f.Close()

		if err = walkFn(f, path); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return xerrors.Errorf("file walk error: %w", err)
	}
	return nil
}

func WriteJSON(filePath string, index interface{}) error {
	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return xerrors.Errorf("unable to create a directory: %w", err)
	}

	f, err := os.Create(filePath)
	if err != nil {
		return xerrors.Errorf("unable to open %s: %w", filePath, err)
	}
	defer f.Close()

	b, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal JSON: %w", err)
	}

	if _, err = f.Write(b); err != nil {
		return xerrors.Errorf("failed to save a file: %w", err)
	}
	return nil
}
