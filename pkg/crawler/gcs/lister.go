package gcs

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

// Lister handles listing artifact names from GCS
type Lister struct {
	client    *Client
	processed atomic.Uint32
	limit     int
	logger    *slog.Logger
}

// NewLister creates a new GCS lister
func NewLister(client *Client, limit int) *Lister {
	return &Lister{
		client: client,
		limit:  limit,
		logger: slog.Default().With(slog.String("component", "lister")),
	}
}

// Run starts the lister component which lists artifacts from GCS
func (l *Lister) Run(ctx context.Context, itemCh chan<- string) error {
	l.logger.Info("Starting GCS artifact lister", slog.Int("limit", l.limit))

	// Create worker pool for parallel processing of prefixes
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10) // Limit concurrent prefix processing

	// First, get top-level prefixes to enable parallel processing
	// And process each prefix in parallel
	var processedPrefixes int
	for prefix, err := range l.client.TopLevelPrefixes(ctx) {
		// Handle errors during iteration immediately
		if err != nil {
			return xerrors.Errorf("failed to list top-level prefixes: %w", err)
		} else if prefix == "maven2/data/" { // Skip data directory as it's not present in Maven Central
			continue
		}

		g.Go(func() error {
			return l.processPrefix(ctx, prefix, itemCh)
		})
		processedPrefixes++
	}

	// Wait for all prefix processing to complete
	if err := g.Wait(); err != nil {
		return xerrors.Errorf("error processing prefixes: %w", err)
	}

	l.logger.Info("GCS artifact listing completed",
		slog.Int("total", int(l.processed.Load())),
		slog.Int("prefixes", processedPrefixes))
	return nil
}

// processPrefix processes a single prefix, listing all matching artifacts
func (l *Lister) processPrefix(ctx context.Context, prefix string, itemCh chan<- string) error {
	// Use the JARSHA1Files iterator from Client
	for item, err := range l.client.JARSHA1Files(ctx, prefix) {
		// Handle errors during iteration immediately
		if err != nil {
			return xerrors.Errorf("error listing JAR SHA1 files for prefix %s: %w", prefix, err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case itemCh <- item:
			// Thread-safe increment using atomic
			processed := l.processed.Add(1)

			// Log every 100,000 processed items
			if processed%100000 == 0 {
				l.logger.Info(fmt.Sprintf("Listed %d artifacts", processed))
			}
		}
	}
	return nil
}
