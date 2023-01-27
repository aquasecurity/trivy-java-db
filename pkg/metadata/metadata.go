package metadata

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
)

const metadataFile = "metadata.json"

type Metadata struct {
	Version      int `json:",omitempty"`
	NextUpdate   time.Time
	UpdatedAt    time.Time
	DownloadedAt time.Time // This field will be filled after downloading.
}

var metaDBDir string

// Path returns the metaData file path
func Path(cacheDir string) string {
	return filepath.Join(cacheDir, metadataFile)
}

func Init(cacheDir string) {
	metaDBDir = Path(cacheDir)
}

// Get returns the file metadata
func Get() (Metadata, error) {
	f, err := os.Open(metaDBDir)
	if err != nil {
		return Metadata{}, xerrors.Errorf("unable to open a file: %w", err)
	}
	defer f.Close()

	var metadata Metadata
	if err = json.NewDecoder(f).Decode(&metadata); err != nil {
		return Metadata{}, xerrors.Errorf("unable to decode metadata: %w", err)
	}
	return metadata, nil
}

func Update(meta Metadata) error {
	if err := os.MkdirAll(filepath.Dir(metaDBDir), 0744); err != nil {
		return xerrors.Errorf("mkdir error: %w", err)
	}

	f, err := os.Create(metaDBDir)
	if err != nil {
		return xerrors.Errorf("unable to open a file: %w", err)
	}
	defer f.Close()

	if err = json.NewEncoder(f).Encode(&meta); err != nil {
		return xerrors.Errorf("unable to decode metadata: %w", err)
	}
	return nil
}

// Delete deletes the file of database metadata
func Delete() error {
	if err := os.Remove(metaDBDir); err != nil {
		return xerrors.Errorf("unable to remove the metadata file: %w", err)
	}
	return nil
}
