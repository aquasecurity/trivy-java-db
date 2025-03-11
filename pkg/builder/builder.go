package builder

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

const updateInterval = time.Hour * 24 * 3 // 3 days

type Builder struct {
	db    db.DB
	meta  db.Client
	clock clock.Clock
}

func NewBuilder(db db.DB, meta db.Client) Builder {
	return Builder{
		db:    db,
		meta:  meta,
		clock: clock.RealClock{},
	}
}

func (b *Builder) Build(cacheDir string) error {
	indexDir := filepath.Join(cacheDir, "indexes")
	count, err := fileutil.Count(indexDir)
	if err != nil {
		return xerrors.Errorf("count error: %w", err)
	}
	bar := pb.StartNew(count)
	defer slog.Info("Build completed")
	defer bar.Finish()

	var indexes []types.Index
	if err := fileutil.Walk(indexDir, func(r io.Reader, path string) error {
		var versions []types.Version
		if err := json.NewDecoder(r).Decode(&versions); err != nil {
			return xerrors.Errorf("failed to decode index: %w", err)
		}
		dir, file := filepath.Split(path)
		dir = strings.TrimPrefix(dir, indexDir)

		artifactID := strings.TrimSuffix(file, ".json")
		groupID := strings.ReplaceAll(dir, "/", ".")
		for _, ver := range versions {
			sha1, _ := hex.DecodeString(ver.SHA1)
			indexes = append(indexes, types.Index{
				GroupID:     groupID,
				ArtifactID:  artifactID,
				Version:     ver.Version,
				SHA1:        sha1,
				ArchiveType: types.JarType,
			})
		}
		bar.Increment()

		if len(indexes) > 1000 {
			if err = b.db.InsertIndexes(indexes); err != nil {
				return xerrors.Errorf("failed to insert index to db: %w", err)
			}
			indexes = []types.Index{}
		}
		return nil
	}); err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	// Insert the remaining indexes
	if err = b.db.InsertIndexes(indexes); err != nil {
		return xerrors.Errorf("failed to insert index to db: %w", err)
	}

	if err := b.db.VacuumDB(); err != nil {
		return xerrors.Errorf("fauled to vacuum db: %w", err)
	}

	// save metadata
	metaDB := db.Metadata{
		Version:    db.SchemaVersion,
		NextUpdate: b.clock.Now().UTC().Add(updateInterval),
		UpdatedAt:  b.clock.Now().UTC(),
	}
	if err := b.meta.Update(metaDB); err != nil {
		return xerrors.Errorf("failed to update metadata: %w", err)
	}

	return nil
}
