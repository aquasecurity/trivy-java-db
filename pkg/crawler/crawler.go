package crawler

import (
	"cmp"
	"context"
	"encoding/csv"
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

	"github.com/aquasecurity/trivy-java-db/pkg/crawler/central"
	"github.com/aquasecurity/trivy-java-db/pkg/crawler/gcs"
	"github.com/aquasecurity/trivy-java-db/pkg/crawler/types"
	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/hash"
	"github.com/aquasecurity/trivy-java-db/pkg/index"
)

// Aggregator writes records to shard files
type Aggregator struct {
	baseDir          string
	shardCount       int
	outFiles         map[int]*os.File
	outWriters       map[int]*csv.Writer
	recordsProcessed int64
	logger           *slog.Logger
}

// SourceType defines the type of artifact source
type SourceType string

const (
	// SourceTypeGCS retrieves artifacts from Google Cloud Storage
	SourceTypeGCS SourceType = "gcs"

	// SourceTypeCentral retrieves artifacts from Maven Central Index
	// https://repo.maven.apache.org/maven2/.index/
	SourceTypeCentral SourceType = "central"
)

// Crawler holds the state for Maven artifact crawling
type Crawler struct {
	dir        string
	cacheDir   string
	http       *retryablehttp.Client
	baseURL    string
	limit      int
	sourceType SourceType

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
	BaseURL      string
	CacheDir     string
	IndexDir     string
	WithoutRetry bool

	// SourceType is the type of artifact source
	// If not specified, GCS is used as default
	SourceType SourceType
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

	slog.Info("Index dir", slog.String("path", opt.IndexDir))
	slog.Info("Sharding", slog.Int("count", opt.Shard))

	return Crawler{
		dir:        opt.IndexDir,
		cacheDir:   opt.CacheDir,
		http:       client,
		baseURL:    opt.BaseURL,
		limit:      opt.Limit,
		shardCount: opt.Shard,
		storedGAVs: make(map[uint64]struct{}),
		mutex:      sync.Mutex{},
		sourceType: cmp.Or(opt.SourceType, SourceTypeGCS), // Default to GCS if not specified
	}, nil
}

func (c *Crawler) Crawl(ctx context.Context) error {
	slog.Info("Starting artifact crawling", slog.String("source", string(c.sourceType)))

	// Load existing indexes to avoid duplicate processing
	if err := c.loadExistingIndexes(); err != nil {
		return xerrors.Errorf("failed to load existing indexes: %w", err)
	}

	// Create a source based on the configured source type
	var source types.Source
	switch c.sourceType {
	case SourceTypeGCS:
		// Create GCS source
		source = gcs.New(c.http, gcs.Options{
			BaseURL:    c.baseURL,
			Limit:      c.limit,
			StoredGAVs: c.storedGAVs,
		})

	case SourceTypeCentral:
		// Create Central Index source
		var err error
		source, err = central.New(c.http, c.baseURL, c.cacheDir, c.storedGAVs)
		if err != nil {
			return xerrors.Errorf("failed to create central index source: %w", err)
		}
	default:
		return xerrors.Errorf("unsupported source type: %s", c.sourceType)
	}

	// Process artifacts using the source
	return c.crawlWithPipeline(ctx, source)
}

// crawlWithPipeline implements the crawling process using a data pipeline architecture:
// Lister → Fetcher → Aggregator
func (c *Crawler) crawlWithPipeline(ctx context.Context, source types.Source) error {
	slog.Info("Starting Maven artifacts crawling pipeline")

	// Create record channel
	recordCh := make(chan types.Record, 1<<16) // 65k buffer

	// Create main error group for pipeline coordination
	g, ctx := errgroup.WithContext(ctx)

	// Create aggregator
	aggregator := &Aggregator{
		baseDir:    c.dir,
		shardCount: c.shardCount,
		outFiles:   make(map[int]*os.File, c.shardCount),
		outWriters: make(map[int]*csv.Writer, c.shardCount),
		logger:     slog.Default().With(slog.String("component", "aggregator")),
	}

	// Stage 1 (Source): Start source workers to stream records
	g.Go(func() error {
		defer close(recordCh) // Close records channel when all records are processed
		return source.Read(ctx, recordCh)
	})

	// Stage 2 (Aggregator): Start aggregator worker to write records to shard files
	g.Go(func() error {
		return aggregator.Run(recordCh)
	})

	// Wait for the pipeline (source, aggregator) to complete
	if err := g.Wait(); err != nil {
		slog.Error("Pipeline error", slog.Any("error", err), slog.Int("artifacts_processed", source.Processed()),
			slog.Int64("records_processed", aggregator.recordsProcessed))
		return xerrors.Errorf("pipeline error: %w", err)
	}

	// Report results
	slog.Info("Artifact crawling completed", slog.Int("artifacts_processed", source.Processed()),
		slog.Int64("records_processed", aggregator.recordsProcessed), slog.Int("artifacts_missing_sha1", source.Failed()))

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

// Run processes records and writes them to appropriate shard files
func (a *Aggregator) Run(recordsCh <-chan types.Record) error {
	a.logger.Info("Starting record aggregator")

	// Flush all writers and close all files when done
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
