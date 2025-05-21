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
	"sync/atomic"
	"unicode"

	"github.com/elireisman/maven-index-reader-go/pkg/config"
	"github.com/elireisman/maven-index-reader-go/pkg/data"
	"github.com/elireisman/maven-index-reader-go/pkg/readers"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler/central/maven"
	"github.com/aquasecurity/trivy-java-db/pkg/crawler/sha1"
	"github.com/aquasecurity/trivy-java-db/pkg/crawler/types"
	"github.com/aquasecurity/trivy-java-db/pkg/hash"
	"github.com/aquasecurity/trivy-java-db/pkg/index"
)

var _ types.Source = (*Source)(nil)

const defaultURL = "https://repo.maven.apache.org/maven2/.index/nexus-maven-repository-index.gz"
const mavenCentralURL = "https://repo.maven.apache.org/maven2"

// NOTE: The SHA1 values in the Maven Central Index are known to be unreliable and should not be trusted.
// Therefore, this implementation follows a two-step process:
//
//   1. Extract a list of GAVC (GroupID, ArtifactID, Version, Classifier) coordinates from the central index.
//   2. For each GAVC, fetch the correct SHA1 value directly from Maven Central repository.
//
// This ensures that only accurate SHA1s are stored and used.
//
// The overall flow can be visualized as:
//
//   +-------------------+         +-------------------+
//   | Central Index     |         | Maven Central     |
//   |  (GAVC list)     |         |  (SHA1 endpoint)  |
//   +--------+----------+         +---------+---------+
//            |                              ^
//            | 1. Extract GAVC list         |
//            v                              |
//   +-------------------+                   |
//   |   This Crawler    |-------------------+
//   |                   |   2. Fetch SHA1 for each GAVC
//   +-------------------+
//
// See: https://github.com/aquasecurity/trivy-java-db/pull/58#issuecomment-2890441162

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

	// --- Channel Pipeline Design ---
	// 1. rawRecordCh: data.Record from index file
	// 2. parsedRecordCh: types.Record without SHA1
	// 3. recordCh: types.Record with SHA1 (final output, provided by caller)

	rawRecordCh := make(chan data.Record, 1024)
	parsedRecordCh := make(chan types.Record, 1024)

	// Start the pipeline stages
	g, ctx := errgroup.WithContext(ctx)

	// Stage 1: Read from index file
	g.Go(func() error {
		defer close(rawRecordCh)
		return s.readFromIndex(rawRecordCh)
	})

	// Stage 2: Parse records
	g.Go(func() error {
		defer close(parsedRecordCh)
		return s.parseRecords(ctx, rawRecordCh, parsedRecordCh)
	})

	// Stage 3: Fetch SHA1s and send to aggregator
	g.Go(func() error {
		return s.fetchSHA1s(ctx, parsedRecordCh, recordCh)
	})

	// Wait for all stages to complete or return on first error
	if err := g.Wait(); err != nil {
		return xerrors.Errorf("pipeline error: %w", err)
	}

	return nil
}

// readFromIndex reads data.Record from the index file and sends them to rawRecordCh
func (s *Source) readFromIndex(rawRecordCh chan<- data.Record) error {
	logger := log.New(io.Discard, "", log.LstdFlags)
	reader := readers.NewChunk(logger, rawRecordCh, config.Index{
		Mode: config.Mode{
			Type: config.All,
		},
		Source: config.Source{
			Type: config.Local,
		},
	}, s.indexPath, nil)

	if err := reader.Read(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// parseRecords parses data.Record into types.Record and validates them
func (s *Source) parseRecords(ctx context.Context, rawRecordCh <-chan data.Record, parsedRecordCh chan<- types.Record) error {
	var record data.Record
	var ok bool
	var count int
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case record, ok = <-rawRecordCh:
			if !ok {
				return nil
			}
		}

		if record.Type() != data.ArtifactAdd {
			continue
		}

		rec := types.Record{
			GroupID:    mustGet[string](record, "groupId"),
			ArtifactID: mustGet[string](record, "artifactId"),
			Version:    mustGet[string](record, "version"),
			Classifier: mustGet[string](record, "classifier"),
		}

		if !s.validateRecord(rec) {
			continue
		}

		gavcHash := hash.GAVC(rec.GroupID, rec.ArtifactID, rec.Version, rec.Classifier)
		if _, exists := s.storedGAVCs[gavcHash]; exists {
			continue
		}
		s.storedGAVCs[gavcHash] = struct{}{}

		count++
		if count%100000 == 0 {
			s.logger.Info(fmt.Sprintf("Parsed %d records", count))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case parsedRecordCh <- rec: // Send the record to the next stage
		}
	}
}

// validateRecord checks if a record is valid
func (s *Source) validateRecord(rec types.Record) bool {
	switch {
	case rec.GroupID == "" || rec.ArtifactID == "" || rec.Version == "":
		return false
	// case containsControlChar(rec.GroupID + rec.ArtifactID + rec.Version + rec.Classifier):
	// 	return false
	case !maven.ValidateClassifier(rec.Classifier):
		return false
	}
	return true
}

// fetchSHA1s fetches SHA1 for each record and sends the enriched record to the output channel
func (s *Source) fetchSHA1s(ctx context.Context, parsedRecordCh <-chan types.Record, recordCh chan<- types.Record) error {
	const batchSize = 200
	var processedCount, fetchedCount atomic.Int64
	g, ctx := errgroup.WithContext(ctx)
	for range batchSize {
		g.Go(func() error {
			var rec types.Record
			var ok bool
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case rec, ok = <-parsedRecordCh:
					if !ok {
						return nil
					}
				}
				sha1, err := s.fetchSHA1(rec)
				if err != nil {
					return xerrors.Errorf("failed to fetch SHA1: %w", err)
				} else if sha1 != index.NotAvailable {
					fetchedCount.Add(1)
				}

				enrichedRec := rec
				enrichedRec.SHA1 = sha1

				select {
				case <-ctx.Done():
					return ctx.Err()
				case recordCh <- enrichedRec:
				}

				current := processedCount.Add(1)
				if current%10000 == 0 {
					s.logger.Info(fmt.Sprintf("Fetched %d SHA1s", current))
				}
			}
		})
	}
	return g.Wait()
}

// fetchSHA1 fetches SHA1 for a single record from Maven Central
func (s *Source) fetchSHA1(rec types.Record) (string, error) {
	groupPath := strings.ReplaceAll(rec.GroupID, ".", "/")
	jarName := rec.ArtifactID + "-" + rec.Version + ".jar"
	url := fmt.Sprintf("%s/%s/%s/%s/%s.sha1",
		mavenCentralURL,
		groupPath,
		rec.ArtifactID,
		rec.Version,
		jarName)

	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return "", xerrors.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", xerrors.Errorf("failed to fetch SHA1: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusNotFound:
		return index.NotAvailable, nil
	default:
		s.logger.Warn("Unexpected status code", slog.String("url", url), slog.Int("status", resp.StatusCode))
		return "", nil
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Warn("Failed to read SHA1 content", slog.String("url", url), slog.Any("error", err))
		return "", nil
	}

	return sha1.Parse(data), nil
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

// containsControlChar returns true if the string contains any control character (ASCII 0x00-0x1F, 0x7F)
func containsControlChar(s string) bool {
	return lo.SomeBy([]rune(s), unicode.IsControl)
}
