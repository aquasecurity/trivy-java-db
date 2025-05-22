package gcs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"

	"golang.org/x/sync/errgroup"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler/central/maven"
	"github.com/aquasecurity/trivy-java-db/pkg/crawler/types"
	"github.com/aquasecurity/trivy-java-db/pkg/hash"
)

// Fetcher fetches SHA1 hash values for artifacts
type Fetcher struct {
	client     *Client
	logger     *slog.Logger
	limit      int
	storedGAVs map[uint64]struct{} // Pre-populated map of GAVs, used as read-only in fetcher
	errCount   atomic.Uint32
}

// NewFetcher creates a new GCS fetcher
func NewFetcher(client *Client, limit int, storedGAVs map[uint64]struct{}) *Fetcher {
	return &Fetcher{
		client:     client,
		limit:      limit,
		storedGAVs: storedGAVs,
		logger:     slog.Default().With(slog.String("component", "fetcher")),
	}
}

// Run starts the fetcher component which downloads SHA1 files
func (f *Fetcher) Run(ctx context.Context, itemCh <-chan string, recordCh chan<- types.Record) error {
	slog.Info("Starting fetcher workers", slog.Int("limit", f.limit))
	// Create fetch worker pool with its own errgroup
	fetchGroup, ctx := errgroup.WithContext(ctx)
	fetchGroup.SetLimit(f.limit)

	// Consume items from channel
	for item := range itemCh {
		fetchGroup.Go(func() error {
			// Fetch SHA1 hash value
			err := f.fetch(ctx, item, recordCh)
			if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil // Normal completion or cancellation
			}

			// For other errors, log and exit if context cancelled
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				slog.Error("Fetcher error", slog.Any("error", err))
				return err // Propagate error to errgroup
			}
		})
	}
	return fetchGroup.Wait()
}

// fetch downloads and processes a single artifact
func (f *Fetcher) fetch(ctx context.Context, item string, recordCh chan<- types.Record) error {
	// Parse artifact coordinates
	groupID, artifactID, version, classifier := parseItemName(item)
	if groupID == "" || artifactID == "" || version == "" {
		return nil
	}

	if !maven.ValidateClassifier(classifier) {
		return nil
	}

	// Skip if already processed
	// NOTE: We only need to check if this GAV has been processed before,
	// no need to store anything as the map is pre-populated
	gavHash := hash.GAVC(groupID, artifactID, version, classifier)
	if _, exists := f.storedGAVs[gavHash]; exists {
		return nil
	}

	// Use the provided Maven client
	sha1, err := f.client.FetchSHA1(ctx, item)
	if err != nil {
		f.logger.Warn("Failed to fetch SHA1", slog.String("item", item), slog.Any("error", err))
		f.errCount.Add(1)
		return nil
	}

	// Send record to next stage
	select {
	case <-ctx.Done():
		return ctx.Err()
	case recordCh <- types.Record{ // Record sent to channel
		GroupID:    groupID,
		ArtifactID: artifactID,
		Version:    version,
		Classifier: classifier,
		SHA1:       sha1,
	}:
	}
	return nil
}

// parseItemName parses item name and returns groupID, artifactID, version and classifier
func parseItemName(name string) (string, string, string, string) {
	name = strings.TrimPrefix(name, "maven2/")
	ss := strings.Split(name, "/")

	// There are cases when name is incorrect (e.g. name doesn't have artifactID)
	if len(ss) < 4 {
		return "", "", "", ""
	}
	groupID := strings.Join(ss[:len(ss)-3], ".")
	artifactID := ss[len(ss)-3]
	version := ss[len(ss)-2]

	// Parse the filename to extract classifier
	// Example format:
	// artifactID-version.jar.sha1 (no classifier)
	// artifactID-version-classifier.jar.sha1 (with classifier)
	filename := ss[len(ss)-1]
	filenameBase := strings.TrimSuffix(filename, ".jar.sha1")

	// Remove artifactID-version prefix
	filenameBase = strings.TrimPrefix(filenameBase, artifactID+"-"+version)

	// If the remaining filename is empty, it means there is no classifier.
	// Typically, classifiers are specified with a hyphen, and trimming the hyphen prefix
	// gives us the classifier (e.g., -lite => lite)
	//
	// However, there are special cases where variants are added after the version without a hyphen.
	// This is not a correct format for classifiers, but we don't know how to handle it properly at the moment.
	// Therefore, we treat any remaining string as a classifier.
	// Example: https://repo.maven.apache.org/maven2/io/github/gnuf0rce/debug-helper/1.3.5/debug-helper-1.3.5.mirai2.jar.sha1 => .mirai2
	classifier := filenameBase
	classifier = strings.TrimPrefix(filenameBase, "-") // e.g. -lite => lite

	return groupID, artifactID, version, classifier
}
