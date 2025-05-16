package central

import (
	"cmp"
	"context"
	"encoding/hex"
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

	"github.com/elireisman/maven-index-reader-go/pkg/config"
	"github.com/elireisman/maven-index-reader-go/pkg/data"
	"github.com/elireisman/maven-index-reader-go/pkg/readers"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler/sha1"
	"github.com/aquasecurity/trivy-java-db/pkg/crawler/types"
	"github.com/aquasecurity/trivy-java-db/pkg/hash"
	"github.com/aquasecurity/trivy-java-db/pkg/index"
)

var _ types.Source = (*Source)(nil)

const defaultURL = "https://repo.maven.apache.org/maven2/.index/nexus-maven-repository-index.gz"
const mavenCentralURL = "https://repo.maven.apache.org/maven2"

// Source implements the crawler.Source interface for Maven Central Index
type Source struct {
	indexPath    string
	url          string
	httpClient   *retryablehttp.Client
	logger       *slog.Logger
	storedGAVCs  map[uint64]struct{}     // GroupID, ArtifactID, Version, Classifier
	missingSHA1s map[uint64]types.Record // GAVC hash -> record without SHA1
	processed    int
	errCount     int
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
		indexPath:    filepath.Join(centralCacheDir, fileName),
		url:          targetURL,
		httpClient:   httpClient,
		logger:       slog.Default().With(slog.String("source", "central")),
		storedGAVCs:  storedGAVs,
		missingSHA1s: make(map[uint64]types.Record),
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

	if err := s.read(ctx, records, errCh, recordCh); err != nil {
		return xerrors.Errorf("failed to read central index: %w", err)
	}

	s.logger.Info("Missing SHA1s", slog.Int("count", len(s.missingSHA1s)))

	// Fetch missing SHA1s from Maven Central directly
	if err := s.fetchMissingSHA1s(ctx, recordCh); err != nil {
		return xerrors.Errorf("failed to fetch missing SHA1s: %w", err)
	}

	return nil
}

func (s *Source) read(ctx context.Context, records <-chan data.Record, errCh chan error, recordCh chan<- types.Record) error {
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
		}

		// Store GAV hash without classifier and delete it if SHA1 is found.
		// Central index may only contain records with classifiers, but records without classifier might exist.
		// For example, ai.ancf.lmos-router:benchmarks only has records with 'sources' or 'javadoc' classifiers in central index,
		// but the record without classifier actually exists and needs to be fetched from remote.
		// https://repo.maven.apache.org/maven2/ai/ancf/lmos-router/benchmarks/0.2.0/benchmarks-0.2.0.jar.sha1
		gavHash := hash.GAVC(rec.GroupID, rec.ArtifactID, rec.Version, "")
		if _, exists := s.storedGAVCs[gavHash]; !exists {
			s.missingSHA1s[gavHash] = types.Record{ // Need only GAV
				GroupID:    rec.GroupID,
				ArtifactID: rec.ArtifactID,
				Version:    rec.Version,
			}
		}

		// Validate the SHA1 hash
		if _, err := hex.DecodeString(rec.SHA1); err != nil || len(rec.SHA1) != 40 {
			s.errCount++
			continue
		}

		// e.g. tests-javadoc, test-fixtures, source-release, debug-sources, etc.
		if strings.HasPrefix(rec.Classifier, "source") || strings.HasPrefix(rec.Classifier, "test") || strings.HasPrefix(rec.Classifier, "debug") ||
			strings.HasPrefix(rec.Classifier, "javadoc") || strings.HasSuffix(rec.Classifier, "javadoc") {
			continue
		}
		switch rec.Classifier {
		case "src", "schemas", "config", "properties", "docs", "readme", "changelog", "cyclonedx", "kdoc":
			continue
		}

		// Skip if already processed
		gavcHash := hash.GAVC(rec.GroupID, rec.ArtifactID, rec.Version, rec.Classifier)
		if _, exists := s.storedGAVCs[gavcHash]; exists {
			continue
		}
		s.storedGAVCs[gavcHash] = struct{}{}
		delete(s.missingSHA1s, gavcHash) // SHA1 found, remove from missingSHA1s

		recordCh <- rec
		s.processed++
		if s.processed%100000 == 0 {
			s.logger.Info(fmt.Sprintf("Parsed %d records", s.processed))
		}
	}
}

// fetchMissingSHA1s fetches missing SHA1s directly from Maven Central repository
func (s *Source) fetchMissingSHA1s(ctx context.Context, recordCh chan<- types.Record) error {
	if len(s.missingSHA1s) == 0 {
		return nil
	}

	// Create an error group for parallel fetching
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(100)

	var processedCount, fetchedCount atomic.Int64

	// Process each missing SHA1
	for _, rec := range s.missingSHA1s {
		g.Go(func() error {
			defer processedCount.Add(1)

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
				return nil // Skip this item on error
			}

			// Execute the request
			resp, err := s.httpClient.Do(req)
			if err != nil {
				return nil // Skip this item on error
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK:
			case http.StatusNotFound: // Store "N/A" to skip this item in the future
			default:
				s.logger.Warn("Unexpected status code", slog.String("url", url), slog.Int("status", resp.StatusCode))
				return nil // Temporary error, skip storing this item to try again next time
			}

			// Read the SHA1 content
			data, err := io.ReadAll(resp.Body)
			if err != nil {
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
				SHA1:       digest,
			}:
			}
			return nil
		})
		if processedCount.Load()%10000 == 0 {
			s.logger.Info(fmt.Sprintf("Fetched %d missing SHA1s out of %d", processedCount.Load(), len(s.missingSHA1s)))
		}
	}

	// Wait for all goroutines to complete
	if err := g.Wait(); err != nil {
		return xerrors.Errorf("error fetching SHA1s: %w", err)
	}

	s.logger.Info("Completed fetching SHA1s from Maven Central",
		slog.Int64("fetched", fetchedCount.Load()),
		slog.Int64("total_attempted", int64(len(s.missingSHA1s))))

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
