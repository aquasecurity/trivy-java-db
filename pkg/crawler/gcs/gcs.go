package gcs

import (
	"context"
	"log/slog"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler/types"
)

var _ types.Source = (*Source)(nil)

// Options represents configuration options for GCS source
type Options struct {
	BaseURL    string
	Limit      int
	StoredGAVs map[uint64]struct{}
}

// Source implements the crawler.Source interface for GCS
type Source struct {
	storedGAVs map[uint64]struct{}
	lister     *Lister
	fetcher    *Fetcher
	logger     *slog.Logger
}

// New creates a new GCS source
func New(httpClient *retryablehttp.Client, opts Options) *Source {
	// Create GCS client
	client := NewClient(httpClient, opts.BaseURL)

	// Calculate limits for lister and fetcher for a better balance
	listerLimit := lo.Ternary(len(opts.StoredGAVs) > 1_000_000, opts.Limit*6/10, opts.Limit*2/10)
	if listerLimit == 0 {
		listerLimit = 1
	}
	fetcherLimit := opts.Limit - listerLimit

	return &Source{
		storedGAVs: opts.StoredGAVs,
		lister:     NewLister(client, listerLimit),
		fetcher:    NewFetcher(client, fetcherLimit, opts.StoredGAVs),
		logger:     slog.Default().With(slog.String("source", "gcs")),
	}
}

// Read streams artifact records from GCS to the provided channel
func (s *Source) Read(ctx context.Context, recordCh chan<- types.Record) error {
	s.logger.Info("Starting GCS record streaming pipeline")

	// Create item channel
	itemCh := make(chan string, 1<<15) // 32k buffer

	// Create error group for coordinating the pipeline
	g, ctx := errgroup.WithContext(ctx)

	// Stage 1 (Lister): Get all iten names suffixing with .jar.sha1 from GCS
	g.Go(func() error {
		defer close(itemCh)
		return s.lister.Run(ctx, itemCh)
	})

	// Stage 2 (Fetcher): Fetch SHA1 hash values for artifacts and send them to the record channel
	g.Go(func() error {
		return s.fetcher.Run(ctx, itemCh, recordCh)
	})

	// Wait for both to complete
	if err := g.Wait(); err != nil {
		return xerrors.Errorf("GCS pipeline error: %w", err)
	}

	return nil
}

func (s *Source) Processed() int {
	return int(s.lister.processed.Load())
}

func (s *Source) Failed() int {
	return int(s.fetcher.errCount.Load())
}
