package central

import (
	"context"
	"log/slog"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler/types"
)

var _ types.Source = (*Source)(nil)

const (
	// MavenCentralIndexURL is the base URL for Maven Central Index
	MavenCentralIndexURL = "https://repo.maven.apache.org/maven2/.index/"

	// MainIndexFile is the main index file name
	MainIndexFile = "nexus-maven-repository-index.gz"
)

// Config represents configuration options for Maven Central Index source
type Config struct {
	CacheDir   string              // Directory to cache downloaded files
	Limit      int                 // Concurrency limit for processing
	StoredGAVs map[uint64]struct{} // Pre-populated map of GAVs
}

// Source implements the crawler.Source interface for Maven Central Index
type Source struct {
	config    Config
	client    *retryablehttp.Client
	logger    *slog.Logger
	processed int
	errCount  int
}

// New creates a new Maven Central Index source
func New(httpClient *retryablehttp.Client, config Config) *Source {
	return &Source{
		config: config,
		client: httpClient,
		logger: slog.Default().With(slog.String("source", "central")),
	}
}

func (s *Source) Read(ctx context.Context, recordCh chan<- types.Record) error {
	s.logger.Info("Starting Maven Central Index processing")
	// TODO: implement

	return nil
}

func (s *Source) Processed() int {
	return s.processed
}

func (s *Source) Failed() int {
	return s.errCount
}
