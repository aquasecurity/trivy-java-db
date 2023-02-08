package utils

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"golang.org/x/xerrors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

func FileWalk(root string, walkFn func(r io.Reader, path string) error) error {
	indexesDir := filepath.Join(root, "indexes_old")
	if err := filepath.WalkDir(indexesDir, func(path string, d fs.DirEntry, err error) error {
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

func WriteJSON(dir string, index *types.Index) error {
	groupIdDir := filepath.Join(dir, index.GroupID)
	if err := os.MkdirAll(groupIdDir, os.ModePerm); err != nil {
		return xerrors.Errorf("unable to create a directory: %w", err)
	}

	fileName := fmt.Sprintf("%s.json", index.ArtifactID)
	filePath := filepath.Join(groupIdDir, fileName)
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
