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
	records     []types.Record      // All GAVC records stored in central index
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

	// Collect GAVC records from central index
	if err := s.read(ctx, records, errCh, recordCh); err != nil {
		return xerrors.Errorf("failed to read central index: %w", err)
	}

	s.logger.Info("Records in central index", slog.Int("count", len(s.records)))

	// Fetch SHA1s from Maven Central
	if err := s.fetchSHA1s(ctx, recordCh); err != nil {
		return xerrors.Errorf("failed to fetch SHA1s: %w", err)
	}

	return nil
}

func (s *Source) read(ctx context.Context, records <-chan data.Record, errCh chan error, recordCh chan<- types.Record) error {
	var record data.Record
	var ok bool
	var count int
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

		if record.Type() != data.ArtifactAdd {
			continue
		}

		// Since SHA1 is not reliable in central index, we need to fetch it from Maven Central
		// cf. https://github.com/aquasecurity/trivy-java-db/pull/58#issuecomment-2890441162
		rec := types.Record{
			GroupID:    mustGet[string](record, "groupId"),
			ArtifactID: mustGet[string](record, "artifactId"),
			Version:    mustGet[string](record, "version"),
			Classifier: mustGet[string](record, "classifier"),
		}

		switch {
		case rec.GroupID == "" || rec.ArtifactID == "" || rec.Version == "":
			continue
		case containsControlChar(rec.GroupID + rec.ArtifactID + rec.Version + rec.Classifier):
			// Skip records with control characters in groupId, artifactId, version or classifier
			continue
		case !maven.ValidateClassifier(rec.Classifier):
			continue
		}

		// Skip if already processed
		gavcHash := hash.GAVC(rec.GroupID, rec.ArtifactID, rec.Version, rec.Classifier)
		if _, exists := s.storedGAVCs[gavcHash]; exists {
			continue
		}
		s.storedGAVCs[gavcHash] = struct{}{}
		s.records = append(s.records, rec)

		count++
		if count%100000 == 0 {
			s.logger.Info(fmt.Sprintf("Parsed %d records", count))
		}
	}
}

// fetchSHA1s fetches SHA1s from Maven Central repository
//
// For each GAVC record collected from the central index, this function constructs the corresponding
// Maven Central URL and fetches the SHA1 checksum directly. This avoids using the unreliable SHA1s
// from the index itself.
func (s *Source) fetchSHA1s(ctx context.Context, recordCh chan<- types.Record) error {
	if len(s.records) == 0 {
		return nil
	}

	// Create an error group for parallel fetching
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(100)

	var processedCount, fetchedCount atomic.Int64

	// Process each record
	for _, rec := range s.records {
		g.Go(func() error {
			defer func() {
				current := processedCount.Add(1)
				if current%10000 == 0 {
					s.logger.Info(fmt.Sprintf("Fetched %d SHA1s out of %d", current, len(s.records)))
				}
			}()

			// Create the SHA1 URL based on GAV coordinates
			// Maven Central URL pattern: baseURL/groupId/artifactId/version/artifactId-version[-classifier].jar.sha1
			// Convert dots in groupId to slashes
			groupPath := strings.ReplaceAll(rec.GroupID, ".", "/")

			// Build jar name: artifactId-version[-classifier].jar
			jarName := rec.ArtifactID + "-" + rec.Version + ".jar"

			// Build the complete URL
			url := fmt.Sprintf("%s/%s/%s/%s/%s.sha1",
				mavenCentralURL,
				groupPath,
				rec.ArtifactID,
				rec.Version,
				jarName)

			// Create the request
			req, err := retryablehttp.NewRequest("GET", url, nil)
			if err != nil {
				return err
			}

			// Execute the request
			resp, err := s.httpClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK:
			case http.StatusForbidden: // e.g. https://repo.maven.apache.org/maven2/com/sourcetohtml/sourcetohtml/1.0.1/sourcetohtml-1.0.1.jar.sha1
			case http.StatusNotFound: // Store "N/A" to skip this item in the future
			default:
				s.logger.Warn("Unexpected status code", slog.String("url", url), slog.Int("status", resp.StatusCode))
				s.errCount++
				return nil // Temporary error, skip storing this item to try again next time
			}

			// Read the SHA1 content
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				s.logger.Warn("Failed to read SHA1 content", slog.String("url", url), slog.Any("error", err))
				s.errCount++
				return nil // Skip this item on error
			}

			// Process the SHA1 content
			digest := sha1.Parse(data)
			if digest != index.NotAvailable {
				fetchedCount.Add(1)
			}

			// Send the record to the output channel
			select {
			case <-ctx.Done():
				return ctx.Err()
			case recordCh <- types.Record{
				GroupID:    rec.GroupID,
				ArtifactID: rec.ArtifactID,
				Version:    rec.Version,
				Classifier: rec.Classifier,
				SHA1:       digest,
			}:
			}
			return nil
		})
	}

	// Wait for all goroutines to complete
	if err := g.Wait(); err != nil {
		return xerrors.Errorf("error fetching SHA1s: %w", err)
	}

	s.logger.Info("Completed fetching SHA1s from Maven Central",
		slog.Int64("fetched", fetchedCount.Load()),
		slog.Int64("total_attempted", int64(len(s.records))),
		slog.Int("errors", s.errCount))

	s.processed = int(fetchedCount.Load())

	return nil
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
