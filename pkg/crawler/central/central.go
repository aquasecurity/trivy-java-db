package central

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/elireisman/maven-index-reader-go/pkg/config"
	"github.com/elireisman/maven-index-reader-go/pkg/data"
	"github.com/elireisman/maven-index-reader-go/pkg/readers"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler/types"
	"github.com/aquasecurity/trivy-java-db/pkg/hash"
)

var _ types.Source = (*Source)(nil)

const defaultURL = "https://repo.maven.apache.org/maven2/.index/nexus-maven-repository-index.gz"

// Source implements the crawler.Source interface for Maven Central Index
type Source struct {
	indexPath   string
	url         string
	httpClient  *retryablehttp.Client
	logger      *slog.Logger
	storedGAVCs map[uint64]struct{} // GroupID, ArtifactID, Version, Classifier
	processed   int
	errCount    int
}

// New creates a new Maven Central Index source
func New(httpClient *retryablehttp.Client, url string, cacheDir string, storedGAVs map[uint64]struct{}) (*Source, error) {
	if cacheDir == "" {
		return nil, xerrors.New("cache directory not specified")
	}

	targetURL := cmp.Or(url, defaultURL)
	fileName := path.Base(targetURL)
	// Ensure the cache directory exists
	centralCacheDir := filepath.Join(cacheDir, "central-index")
	if err := os.MkdirAll(centralCacheDir, 0755); err != nil {
		return nil, xerrors.Errorf("failed to create cache directory: %w", err)
	}

	return &Source{
		indexPath:   filepath.Join(centralCacheDir, fileName),
		url:         targetURL,
		httpClient:  httpClient,
		logger:      slog.Default().With(slog.String("source", "central")),
		storedGAVCs: storedGAVs,
	}, nil
}

// downloadIndex downloads the index file to a cached location and returns the path
func (s *Source) downloadIndex() (err error) {
	// Check if the file already exists in cache
	if _, err := os.Stat(s.indexPath); err == nil {
		s.logger.Info("Using cached Maven Central Index", slog.String("path", s.indexPath))
		return nil
	}

	s.logger.Info("Downloading Maven Central Index", slog.String("url", s.url), slog.String("path", s.indexPath))

	// Create the output file
	outFile, err := os.Create(s.indexPath)
	if err != nil {
		return xerrors.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		if err != nil {
			os.Remove(s.indexPath)
		}
	}()
	defer outFile.Close()

	// Create the request
	req, err := retryablehttp.NewRequest("GET", s.url, nil)
	if err != nil {
		return xerrors.Errorf("failed to create request: %w", err)
	}

	// Execute the request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return xerrors.Errorf("failed to download index: %w", err)
	}
	defer resp.Body.Close()

	// Check for successful response
	if resp.StatusCode != http.StatusOK {
		return xerrors.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Copy the response body to the output file
	n, err := io.Copy(outFile, resp.Body)
	if err != nil {
		return xerrors.Errorf("failed to save index file: %w", err)
	}

	s.logger.Info("Downloaded Maven Central Index", slog.String("path", s.indexPath), slog.Int64("size", n))

	return nil
}

func (s *Source) Read(ctx context.Context, recordCh chan<- types.Record) error {
	s.logger.Info("Starting Maven Central Index processing")

	// Download/Get the index file first
	if err := s.downloadIndex(); err != nil {
		return xerrors.Errorf("failed to get index file: %w", err)
	}

	// Make a queue to buffer records scanned from the index
	records := make(chan data.Record, 64)

	// Create a file-based reader
	logger := log.New(io.Discard, "", log.LstdFlags)
	reader := readers.NewChunk(logger, records, config.Index{
		Mode: config.Mode{
			Type: config.All,
		},
		Source: config.Source{
			Type: config.Local, // Use local file source
		},
	}, s.indexPath, nil)

	errCh := make(chan error)
	defer close(errCh)

	go func() {
		defer close(records)
		if err := reader.Read(); err != nil && !errors.Is(err, io.EOF) {
			errCh <- xerrors.Errorf("failed to read central index: %w", err)
		}
	}()

	var record data.Record
	var ok bool
	for {
		select {
		case record, ok = <-records:
			if !ok {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		}

		if record.Type() != data.ArtifactAdd || record.Get("fileExtension") != "jar" {
			continue
		}

		rec := types.Record{
			GroupID:    mustGet[string](record, "groupId"),
			ArtifactID: mustGet[string](record, "artifactId"),
			Version:    mustGet[string](record, "version"),
			Classifier: mustGet[string](record, "classifier"),
			SHA1:       mustGet[string](record, "sha1"),
		}

		if rec.GroupID == "" || rec.ArtifactID == "" || rec.Version == "" {
			continue
		} else if rec.SHA1 == "" {
			s.errCount++
			continue
		}

		// e.g. tests-javadoc, test-fixtures, source-release, debug-sources, etc.
		if strings.HasPrefix(rec.Classifier, "source") || strings.HasPrefix(rec.Classifier, "test") || strings.HasPrefix(rec.Classifier, "debug") ||
			strings.HasPrefix(rec.Classifier, "javadoc") || strings.HasSuffix(rec.Classifier, "javadoc") {
			continue
		}
		switch rec.Classifier {
		case "metadata", "src", "schemas", "config", "properties", "docs", "readme", "changelog", "cyclonedx", "kdoc":
			continue
		}

		// Skip if already processed
		gavHash := hash.GAVC(rec.GroupID, rec.ArtifactID, rec.Version, rec.Classifier)
		if _, exists := s.storedGAVCs[gavHash]; exists {
			continue
		}
		s.storedGAVCs[gavHash] = struct{}{}

		recordCh <- rec
		s.processed++
		if s.processed%100000 == 0 {
			s.logger.Info(fmt.Sprintf("Parsed %d records", s.processed))
		}
	}
}

func (s *Source) Processed() int {
	return s.processed
}

func (s *Source) Failed() int {
	return s.errCount
}

func mustGet[T any](record data.Record, key string) T {
	v, _ := record.Get(key).(T)
	return v
}
