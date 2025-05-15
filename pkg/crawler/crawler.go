package crawler

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/hash"
	"github.com/aquasecurity/trivy-java-db/pkg/index"
)

const (
	gcsURL = "https://storage.googleapis.com/"
)

// Record represents a Maven artifact index with SHA1 hash
type Record struct {
	GroupID    string
	ArtifactID string
	Version    string
	Classifier string // e.g. "lite", "cuda10-1"
	SHA1       string
}

// Lister handles listing artifact names from GCS
type Lister struct {
	client    *GCS
	gcsURL    string
	processed atomic.Uint32
	limit     int
	logger    *slog.Logger
}

// Fetcher fetches SHA1 hash values for artifacts
type Fetcher struct {
	client     *GCS
	gcrURL     string
	logger     *slog.Logger
	limit      int
	storedGAVs map[uint64]struct{} // Pre-populated map of GAVs, used as read-only in fetcher
	errCount   atomic.Uint32
}

// Aggregator writes records to shard files
type Aggregator struct {
	baseDir          string
	shardCount       int
	outFiles         map[int]*os.File
	outWriters       map[int]*csv.Writer
	recordsProcessed int64
	logger           *slog.Logger
}

// Crawler holds the state for Maven artifact crawling
type Crawler struct {
	dir  string
	http *retryablehttp.Client

	gcsURL string
	limit  int

	// Fields related to sharding
	shardCount int
	// storedGAVs is a map of stored GAV hashes to prevent duplicate processing.
	// We use a regular map with mutex instead of sync.Map to avoid unnecessary sync.Map -> map conversion
	// when passing to fetcher as read-only.
	storedGAVs map[uint64]struct{}
	// mutex protects access to storedGAVs during concurrent loading
	mutex sync.Mutex
}

type Option struct {
	Shard        int
	Limit        int
	GcsURL       string
	CacheDir     string
	IndexDir     string
	WithoutRetry bool
}

func NewCrawler(opt Option) (Crawler, error) {
	if opt.Limit < 2 {
		return Crawler{}, xerrors.Errorf("limit must be >= 2, got %d", opt.Limit)
	}
	client := retryablehttp.NewClient()
	client.RetryMax = 10
	if opt.WithoutRetry {
		client.RetryMax = 0
	}
	client.Logger = slog.Default()
	client.RetryWaitMin = 1 * time.Minute
	client.RetryWaitMax = 5 * time.Minute
	client.Backoff = retryablehttp.LinearJitterBackoff
	client.ResponseLogHook = func(_ retryablehttp.Logger, resp *http.Response) {
		if resp.StatusCode != http.StatusOK {
			slog.Warn("Unexpected http response", slog.String("url", resp.Request.URL.String()), slog.String("status", resp.Status))
		}
	}
	client.ErrorHandler = func(resp *http.Response, err error, numTries int) (*http.Response, error) {
		logger := slog.Default()
		if resp != nil {
			logger = slog.With(slog.String("url", resp.Request.URL.String()), slog.Int("status_code", resp.StatusCode),
				slog.Int("num_tries", numTries))
		}

		if err != nil {
			logger = logger.With(slog.String("error", err.Error()))
		}
		logger.Error("HTTP request failed after retries")
		return resp, xerrors.Errorf("HTTP request failed after retries: %w", err)
	}

	if opt.GcsURL == "" {
		opt.GcsURL = gcsURL
	}

	slog.Info("Index dir", slog.String("path", opt.IndexDir))
	slog.Info("Sharding", slog.Int("count", opt.Shard))

	return Crawler{
		dir:        opt.IndexDir,
		http:       client,
		gcsURL:     opt.GcsURL,
		limit:      opt.Limit,
		shardCount: opt.Shard,
		storedGAVs: make(map[uint64]struct{}),
		mutex:      sync.Mutex{},
	}, nil
}

func (c *Crawler) Crawl(ctx context.Context) error {
	slog.Info("Crawl GCS and save indexes")

	if err := c.loadExistingIndexes(); err != nil {
		return xerrors.Errorf("failed to load existing indexes: %w", err)
	}

	return c.crawlWithPipeline(ctx)
}

// crawlWithPipeline implements the crawling process using a data pipeline architecture:
// Lister → Fetcher → Aggregator
func (c *Crawler) crawlWithPipeline(ctx context.Context) error {
	slog.Info("Starting Maven artifacts crawling pipeline")

	// Create channels for the pipeline stages
	itemCh := make(chan string, 1<<15)   // 32k buffer
	recordCh := make(chan Record, 1<<16) // 65k buffer

	// Create main error group for pipeline coordination
	g, ctx := errgroup.WithContext(ctx)

	gcs := NewGCS(c.http, c.gcsURL)

	// When we have already processed GAVs, most GAVs will be skipped during SHA1 fetching,
	// resulting in very few actual fetch operations in the fetcher. This allows us to
	// increase the parallelism of the listing process.
	listerLimit := lo.Ternary(len(c.storedGAVs) > 1_000_000, c.limit*6/10, c.limit*2/10)
	if listerLimit == 0 {
		listerLimit = 1
	}
	fetcherLimit := c.limit - listerLimit

	// Create component instances
	lister := &Lister{
		client: gcs,
		gcsURL: c.gcsURL,
		limit:  listerLimit,
		logger: slog.Default().With(slog.String("component", "lister")),
	}

	fetcher := &Fetcher{
		client:     gcs,
		gcrURL:     c.gcsURL,
		limit:      fetcherLimit,
		storedGAVs: c.storedGAVs, // Direct reference to the map as read-only
		logger:     slog.Default().With(slog.String("component", "fetcher")),
	}

	aggregator := &Aggregator{
		baseDir:    c.dir,
		shardCount: c.shardCount,
		outFiles:   make(map[int]*os.File, c.shardCount),
		outWriters: make(map[int]*csv.Writer, c.shardCount),
		logger:     slog.Default().With(slog.String("component", "aggregator")),
	}

	// Stage 1 (Lister): Get all item names suffixing with .jar.sha1 from GCS
	g.Go(func() error {
		defer close(itemCh) // Close item channel when lister is done
		return lister.Run(ctx, itemCh)
	})

	// Stage 2 (Fetcher): Start fetcher workers to fetch SHA1 hash values
	g.Go(func() error {
		defer close(recordCh) // Close records channel when all fetchers are done
		return fetcher.Run(ctx, itemCh, recordCh)
	})

	// Stage 3 (Aggregator): Start aggregator worker to write records to shard files
	g.Go(func() error {
		return aggregator.Run(recordCh)
	})

	// Wait for the pipeline (lister, fetchers, aggregator) to complete
	if err := g.Wait(); err != nil {
		slog.Error("Pipeline error", slog.Any("error", err), slog.Int("artifacts_processed", int(lister.processed.Load())),
			slog.Int64("records_processed", aggregator.recordsProcessed))
		return xerrors.Errorf("pipeline error: %w", err)
	}

	// Report results
	slog.Info("Crawl pipeline completed", slog.Int("artifacts_processed", int(lister.processed.Load())),
		slog.Int64("records_processed", aggregator.recordsProcessed), slog.Int("artifacts_missing_sha1", int(fetcher.errCount.Load())))

	return nil
}

// Load existing indexes
func (c *Crawler) loadExistingIndexes() error {
	if !fileutil.Exists(c.dir) {
		return nil
	}

	slog.Info("Loading existing indexes from TSV files")

	// Use atomic.Uint32 for counter
	var count atomic.Uint32

	// Create an error group to load indexes in parallel
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(runtime.NumCPU()) // Parallel loading based on CPU count

	// Process TSV files using fileutil.Walk
	err := filepath.WalkDir(c.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return xerrors.Errorf("walk error: %w", err)
		} else if d.IsDir() {
			return nil
		}

		// Process only TSV files
		if !strings.HasSuffix(path, ".tsv") {
			return nil
		}

		// Create a goroutine for each file
		g.Go(func() error {
			// Track records in this file
			var fileCount uint32

			reader, err := index.Open(path)
			if err != nil {
				return xerrors.Errorf("open error: %w", err)
			}
			defer reader.Close()

			// Process all records in this file
			for {
				select {
				case <-ctx.Done():
					return ctx.Err() // Handle cancellation
				default:
				}

				// Read one record
				record, err := reader.Read()
				if err == io.EOF {
					break
				}
				if err != nil {
					// Log but continue on error
					slog.Warn("Error reading TSV record",
						slog.String("file", path),
						slog.Any("error", err))
					continue
				}

				// Need at least GroupID, ArtifactID, Version
				if len(record) < 3 {
					continue // Skip invalid records
				}

				groupID, artifactID, version, classifier := record[0], record[1], record[2], record[3]
				if classifier == "-" {
					classifier = ""
				}

				gavHash := hash.GAVC(groupID, artifactID, version, classifier)

				c.mutex.Lock()
				c.storedGAVs[gavHash] = struct{}{}
				c.mutex.Unlock()

				fileCount++
			}

			// Update the global counter
			count.Add(fileCount)

			return nil
		})
		return nil
	})

	if err != nil {
		return xerrors.Errorf("error walking TSV files: %w", err)
	}

	// Wait for all processing to complete
	if err = g.Wait(); err != nil {
		return xerrors.Errorf("error processing TSV files: %w", err)
	}

	slog.Info("Loaded total records", slog.Int("count", int(count.Load())))
	return nil
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

	l.logger.Info("GCS artifact listing completed", slog.Int("total", int(l.processed.Load())), slog.Int("prefixes", processedPrefixes))
	return nil
}

// processPrefix processes a single prefix, listing all matching artifacts
func (l *Lister) processPrefix(ctx context.Context, prefix string, itemCh chan<- string) error {
	// Use the JARSHA1Files iterator from GCS
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
			// NOTE: The return value 'processed'is just to preserve the current value for logging.
			processed := l.processed.Add(1)

			// Log every 100,000 processed items
			if processed%100000 == 0 {
				l.logger.Info(fmt.Sprintf("Listed %d artifacts", processed))
			}
		}
	}
	return nil
}

// Run starts the fetcher component which downloads SHA1 files
func (f *Fetcher) Run(ctx context.Context, itemCh <-chan string, recordCh chan<- Record) error {
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

func (f *Fetcher) fetch(ctx context.Context, item string, recordCh chan<- Record) error {
	// Parse artifact coordinates
	groupID, artifactID, version, classifier := parseItemName(item)
	if groupID == "" || artifactID == "" {
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
	if sha1 == index.NotAvailable {
		f.errCount.Add(1)
	} else if err != nil {
		f.logger.Warn("Failed to fetch SHA1", slog.String("item", item), slog.Any("error", err))
		return nil
	}

	// Send record to next stage
	select {
	case <-ctx.Done():
		return ctx.Err()
	case recordCh <- Record{ // Record sent to channel
		GroupID:    groupID,
		ArtifactID: artifactID,
		Version:    version,
		Classifier: classifier,
		SHA1:       sha1,
	}:
	}
	return nil
}

// Run processes records and writes them to appropriate shard files
func (a *Aggregator) Run(recordsCh <-chan Record) error {
	a.logger.Info("Starting record aggregator")

	// Close all writers and files when done
	defer a.closeWriters()

	for rec := range recordsCh {
		// Calculate shard index based on GroupID+ArtifactID
		shardIdx := int(hash.GA(rec.GroupID, rec.ArtifactID) % uint64(a.shardCount))

		// Get or create writer for this shard
		writer, err := a.newWriter(shardIdx)
		if err != nil {
			a.logger.Error("Failed to get writer",
				slog.Int("shard", shardIdx),
				slog.Any("error", err))
			return xerrors.Errorf("failed to get writer: %w", err)
		}

		// Write TSV record: GroupID, ArtifactID, Version, SHA1
		err = writer.Write([]string{
			rec.GroupID,
			rec.ArtifactID,
			rec.Version,
			rec.Classifier,
			rec.SHA1,
		})
		if err != nil {
			a.logger.Error("Failed to write record",
				slog.Int("shard", shardIdx),
				slog.Any("error", err))
			return xerrors.Errorf("failed to write record: %w", err)
		}

		// Periodically flush to disk
		a.recordsProcessed++
		if a.recordsProcessed%100000 == 0 {
			// Flush all writers
			a.flushWriters()
			a.logger.Info(fmt.Sprintf("Processed %d records", a.recordsProcessed))
		}
	}

	// Final flush of CSV writers and buffer writers
	a.flushWriters()

	a.logger.Info("Aggregator completed", slog.Int64("total_records", a.recordsProcessed))
	return nil
}

// newWriter returns a CSV writer for the specified shard, creating it if necessary
func (a *Aggregator) newWriter(shardIdx int) (*csv.Writer, error) {
	// Return existing writer if we have one
	if writer, exists := a.outWriters[shardIdx]; exists {
		return writer, nil
	}

	// Determine format string based on number of shards
	digits := digitsFor(a.shardCount)

	// Format the shard index as a hex string with appropriate padding
	hexIndex := fmt.Sprintf("%0*x", digits, shardIdx)

	// Create hierarchical directory structure with 2 characters per level
	// For example: 0001 -> 00/01.tsv, 0a2b -> 0a/2b.tsv

	// Split hex string into segments of 2 characters using lo.ChunkString
	segments := lo.ChunkString(hexIndex, 2)

	// Last segment is the filename
	subPath := filepath.Join(segments...) + ".tsv"
	outPath := filepath.Join(a.baseDir, subPath)

	// Create subdirectories
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return nil, xerrors.Errorf("failed to create shard directory: %w", err)
	}

	// Create or open the TSV file
	file, err := os.OpenFile(outPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, xerrors.Errorf("failed to open file: %w", err)
	}

	// Create buffered writer
	writer := csv.NewWriter(file)
	writer.Comma = '\t' // Use tab as delimiter

	// Store references
	a.outFiles[shardIdx] = file
	a.outWriters[shardIdx] = writer

	return writer, nil
}

// flushWriters flushes all CSV writers
func (a *Aggregator) flushWriters() {
	for shardIdx, writer := range a.outWriters {
		writer.Flush()
		if err := writer.Error(); err != nil {
			a.logger.Error("Error flushing CSV writer", slog.Int("shard", shardIdx), slog.Any("error", err))
		}
	}
}

// closeWriters closes all open files
func (a *Aggregator) closeWriters() {
	// First flush CSV writers
	a.flushWriters()

	// Close all files
	for shardIdx, file := range a.outFiles {
		if err := file.Close(); err != nil {
			a.logger.Error("Failed to close file", slog.Int("shard", shardIdx), slog.Any("error", err))
		}
	}
}

// digitsFor calculates the number of hex digits needed to represent n values
func digitsFor(n int) int {
	d := int(math.Ceil(math.Log(float64(n)) / math.Log(16)))
	if d < 2 {
		return 2
	}
	return d
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

	// If the filename is empty, it means there is no classifier
	var classifier string
	if strings.HasPrefix(filenameBase, "-") {
		classifier = strings.TrimPrefix(filenameBase, "-")
	}

	return groupID, artifactID, version, classifier
}
