package central

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"

	"github.com/elireisman/maven-index-reader-go/pkg/config"
	"github.com/elireisman/maven-index-reader-go/pkg/data"
	"github.com/elireisman/maven-index-reader-go/pkg/readers"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler/types"
	"github.com/aquasecurity/trivy-java-db/pkg/hash"
)

var _ types.Source = (*Source)(nil)

const defaultURL = "https://repo.maven.apache.org/maven2/.index/nexus-maven-repository-index.gz"

// Source implements the crawler.Source interface for Maven Central Index
type Source struct {
	logger     *slog.Logger
	reader     readers.Chunk
	records    chan data.Record
	storedGAVs map[uint64]struct{}
	processed  int
	errCount   int
}

// New creates a new Maven Central Index source
func New(url string, storedGAVs map[uint64]struct{}) *Source {
	// Disable logging in the third-party library
	logger := log.New(io.Discard, "", log.LstdFlags)

	// Make a queue to buffer records scanned from the index
	records := make(chan data.Record, 64)

	target := cmp.Or(url, defaultURL)
	chunk := readers.NewChunk(logger, records, config.Index{
		Mode: config.Mode{
			Type: config.All,
		},
		Source: config.Source{
			Type: config.HTTP,
		},
	}, target, nil)

	return &Source{
		reader:     chunk,
		records:    records,
		storedGAVs: storedGAVs,
		logger:     slog.Default().With(slog.String("source", "central")),
	}
}

func (s *Source) Read(ctx context.Context, recordCh chan<- types.Record) error {
	s.logger.Info("Starting Maven Central Index processing")

	var errCh chan error
	defer close(errCh)

	go func() {
		defer close(s.records)
		if err := s.reader.Read(); err != nil {
			errCh <- xerrors.Errorf("failed to read central index: %w", err)
		}
	}()

	for record := range s.records {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		default:
		}

		if record.Type() != data.ArtifactAdd {
			continue
		}

		groupID, ok := record.Get("groupId").(string)
		if !ok {
			continue
		}

		artifactID, ok := record.Get("artifactId").(string)
		if !ok {
			continue
		}

		versionDir, ok := record.Get("version").(string)
		if !ok {
			continue
		}

		sha1, ok := record.Get("sha1").(string)
		if !ok {
			continue
		}

		if groupID == "" || artifactID == "" || versionDir == "" || sha1 == "" {
			s.errCount++
			continue
		}

		// Skip if already processed
		// NOTE: We only need to check if this GAV has been processed before,
		// no need to store anything as the map is pre-populated
		gavHash := hash.GAV(groupID, artifactID, versionDir)
		if _, exists := s.storedGAVs[gavHash]; exists {
			continue
		}

		recordCh <- types.Record{
			GroupID:    groupID,
			ArtifactID: artifactID,
			VersionDir: versionDir,
			Version:    "-", // Assume that version is the same as versionDir in Central Index
			SHA1:       sha1,
		}
		s.processed++
		if s.processed%100000 == 0 {
			s.logger.Info(fmt.Sprintf("Parsed %d records", s.processed))
		}
	}
	return nil
}

func (s *Source) Processed() int {
	return s.processed
}

func (s *Source) Failed() int {
	return s.errCount
}
