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

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
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

func (b *Builder) Build(indexDir string) error {
	count, err := fileutil.Count(indexDir)
	if err != nil {
		return xerrors.Errorf("count error: %w", err)
	}
	bar := pb.StartNew(count)
	defer slog.Info("Build completed")
	defer bar.Finish()

	var indexes []types.Index
	if err := fileutil.Walk(indexDir, func(r io.Reader, path string) error {
		index := &crawler.Index{}
		if err := json.NewDecoder(r).Decode(index); err != nil {
			return xerrors.Errorf("failed to decode index: %w", err)
		}

		// Convert directory path to groupID and artifactID
		rel, err := filepath.Rel(indexDir, path)
		if err != nil {
			return xerrors.Errorf("failed to get relative path: %w", err)
		}
		dir := filepath.Dir(rel)
		groupID, artifactID := filepath.Split(dir)
		groupID = strings.ReplaceAll(filepath.Clean(groupID), string(filepath.Separator), ".")

		for _, ver := range index.Versions {
			sha1, err := hex.DecodeString(ver.SHA1)
			if err != nil {
				slog.Error("failed to decode SHA1", slog.Any("error", err), slog.String("sha1", ver.SHA1))
				continue // Should never happen as we validate SHA1 in crawler
			}

			indexes = append(indexes, types.Index{
				GroupID:     groupID,
				ArtifactID:  artifactID,
				Version:     ver.Version,
				SHA1:        sha1,
				ArchiveType: index.Packaging,
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
