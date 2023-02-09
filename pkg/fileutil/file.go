package fileutil

import (
	"encoding/json"
	"golang.org/x/xerrors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

func Walk(root string, walkFn func(r io.Reader, path string) error) error {
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

// Count counts a number of files under the specified root directory.
func Count(root string) (int, error) {
	var count int
	err := Walk(root, func(_ io.Reader, _ string) error {
		count++
		return nil
	})
	if err != nil {
		return 0, xerrors.Errorf("file count error: %w", err)
	}
	return count, nil
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
