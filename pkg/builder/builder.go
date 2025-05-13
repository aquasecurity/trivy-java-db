package builder

import (
	"encoding/hex"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/index"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/cheggaaa/pb/v3"
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
	slog.Info("Building the index database")
	count, err := fileutil.Count(indexDir)
	if err != nil {
		return xerrors.Errorf("count error: %w", err)
	}
	bar := pb.StartNew(count)
	defer slog.Info("Build completed", slog.Int("count", count))
	defer bar.Finish()

	err = fileutil.Walk(indexDir, func(r io.Reader, path string) error {
		// 	// Process only TSV files
		if filepath.Ext(path) != ".tsv" {
			return nil
		}
		defer bar.Increment()

		// Create a CSV reader for TSV format
		reader := index.NewReader(r)

		var indexes, classifierIndexes []types.Index

		// Process all records in this file
		for {
			// Read one record
			record, err := reader.Read()
			if err == io.EOF {
				break
			} else if err != nil {
				// Log but continue on error
				slog.Warn("Error reading TSV record", slog.String("file", path), slog.Any("error", err))
				continue
			}

			// Need at least GroupID, ArtifactID, Version
			if len(record) != 5 {
				continue // Skip invalid records
			}

			groupID, artifactID, version, classifier, sha1str := record[0], record[1], record[2], record[3], record[4]
			if sha1str == index.NotAvailable {
				continue // Skip records with no SHA1
			}

			sha1, err := hex.DecodeString(sha1str)
			if err != nil {
				slog.Error("failed to decode SHA1", slog.Any("error", err), slog.String("sha1", sha1str))
				return xerrors.Errorf("failed to decode SHA1: %w", err) // Should never happen as we validate SHA1 in crawler
			}

			index := types.Index{
				GroupID:     groupID,
				ArtifactID:  artifactID,
				Version:     version,
				Classifier:  classifier,
				SHA1:        sha1,
				ArchiveType: types.JarType, // Always JAR for now
			}

			if index.Classifier == "" {
				// Empty classifier
				// e.g.  https://repo.maven.apache.org/maven2/ai/rapids/cudf/0.14/cudf-0.14.jar.sha1
				indexes = append(indexes, index)
			} else {
				// Non-empty classifier
				// e.g. https://repo.maven.apache.org/maven2/ai/rapids/cudf/0.14/cudf-0.14-cuda10-1.jar.sha1 (cuda10-1 is classifier)
				classifierIndexes = append(classifierIndexes, index)
			}
		}

		// Insert indexes without classifier first, and then with classifier so they will not override the indexes with classifier.
		// The classifier indexes might be rejected by the unique constraint on sha1.
		indexes = append(indexes, classifierIndexes...)
		if err := b.db.InsertIndexes(indexes); err != nil {
			return xerrors.Errorf("failed to insert index to db: %w", err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
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
