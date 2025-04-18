package crawler

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"math/rand"
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
)

const (
	gcsURL = "https://storage.googleapis.com/"
)

// Record represents a Maven artifact index with SHA1 hash
type Record struct {
	GroupID    string
	ArtifactID string
	Version    string
	VersionDir string
	SHA1       string
}

// Lister handles listing artifact names from GCS
type Lister struct {
	client    *retryablehttp.Client
	gcsURL    string
	processed int
	logger    *slog.Logger
}

// Fetcher fetches SHA1 hash values for artifacts
type Fetcher struct {
	client     *retryablehttp.Client
	gcrURL     string
	logger     *slog.Logger
	limit      int
	storedGAVs map[uint64]struct{} // Pre-populated map of GAVs, used as read-only in fetcher
	wrongSHA1s []string
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

	// Create component instances
	lister := &Lister{
		client: c.http,
		gcsURL: c.gcsURL,
		logger: slog.Default().With(slog.String("component", "lister")),
	}

	fetcher := &Fetcher{
		client:     c.http,
		gcrURL:     c.gcsURL,
		limit:      c.limit,
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
		slog.Error("Pipeline error", slog.Any("error", err), slog.Int("artifacts_processed", lister.processed),
			slog.Int64("records_processed", aggregator.recordsProcessed))
		return xerrors.Errorf("pipeline error: %w", err)
	}

	// Report results
	slog.Info("Crawl pipeline completed", slog.Int("artifacts_processed", lister.processed),
		slog.Int64("records_processed", aggregator.recordsProcessed), slog.Int("error_count", len(fetcher.wrongSHA1s)))

	for _, wrongSHA1 := range fetcher.wrongSHA1s {
		slog.Error("Wrong SHA1", slog.String("error", wrongSHA1))
	}

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

			f, err := os.Open(path)
			if err != nil {
				return xerrors.Errorf("open error: %w", err)
			}
			defer f.Close()

			// Create a CSV reader for TSV format
			reader := csv.NewReader(f)
			reader.Comma = '\t' // Use tab as delimiter
			reader.FieldsPerRecord = 5
			reader.ReuseRecord = true // Reuse memory for performance

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

				groupID, artifactID, versionDir := record[0], record[1], record[2]

				// Hash GAV and add to map
				gavHash := hashGAV(groupID, artifactID, versionDir)
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
	if err := g.Wait(); err != nil {
		return xerrors.Errorf("error processing TSV files: %w", err)
	}

	slog.Info("Loaded total records", slog.Int("count", int(count.Load())))
	return nil
}

// Run starts the lister component which lists artifacts from GCS
func (l *Lister) Run(ctx context.Context, itemCh chan<- string) error {
	l.logger.Info("Starting GCS artifact lister")

	url := l.gcsURL + "storage/v1/b/maven-central/o/"
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return xerrors.Errorf("unable to create a HTTP request: %w", err)
	}

	// Configure the query parameters for GCS API
	query := req.URL.Query()
	query.Set("prefix", "maven2/")
	query.Set("matchGlob", "**/*.jar.sha1")
	query.Set("maxResults", "5000")
	req.URL.RawQuery = query.Encode()

	// Fetch artifacts page by page
	for {
		r, err := l.fetchItems(ctx, req)
		if err != nil {
			return xerrors.Errorf("unable to get items: %w", err)
		}

		for _, item := range r.Items {
			// Don't process sources, test, javadocs, scaladoc files
			if strings.HasSuffix(item.Name, "sources.jar.sha1") || strings.HasSuffix(item.Name, "test.jar.sha1") ||
				strings.HasSuffix(item.Name, "tests.jar.sha1") || strings.HasSuffix(item.Name, "javadoc.jar.sha1") ||
				strings.HasSuffix(item.Name, "scaladoc.jar.sha1") {
				continue
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case itemCh <- item.Name:
				l.processed++
			}
		}

		// Check if there are more pages
		if r.NextPageToken == "" {
			break
		}

		// Set up next page token
		query.Set("pageToken", r.NextPageToken)
		req.URL.RawQuery = query.Encode()
	}

	l.logger.Info("GCS artifact listing completed", slog.Int("total", l.processed))
	return nil
}

// fetchItems retrieves a page of items from GCS API
func (l *Lister) fetchItems(ctx context.Context, req *retryablehttp.Request) (GcsApiResponse, error) {
	resp, err := httpGet(ctx, l.client, req.URL.String())
	if err != nil {
		return GcsApiResponse{}, xerrors.Errorf("http error (%s): %w", req.URL.String(), err)
	}
	defer resp.Body.Close()

	var res GcsApiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return GcsApiResponse{}, xerrors.Errorf("unable to parse API response: %w", err)
	}

	return res, nil
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
	groupID, artifactID, versionDir, version := parseItemName(item)
	if groupID == "" || artifactID == "" {
		return nil
	}

	// Skip if already processed
	// NOTE: We only need to check if this GAV has been processed before,
	// no need to store anything as the map is pre-populated
	gavHash := hashGAV(groupID, artifactID, versionDir)
	if _, exists := f.storedGAVs[gavHash]; exists {
		return nil
	}

	// Fetch SHA1 value
	sha1, err := f.fetchSHA1(ctx, item)
	if err != nil {
		f.logger.Warn("Failed to fetch SHA1", slog.String("item", item), slog.Any("error", err))
		return nil
	} else if sha1 == "" {
		return nil
	}

	// Send record to next stage
	select {
	case <-ctx.Done():
		return ctx.Err()
	case recordCh <- Record{ // Record sent to channel
		GroupID:    groupID,
		ArtifactID: artifactID,
		VersionDir: versionDir,
		Version:    version,
		SHA1:       sha1,
	}:
	}
	return nil
}

// fetchSHA1 downloads and extracts SHA1 hash for an artifact
func (f *Fetcher) fetchSHA1(ctx context.Context, itemName string) (string, error) {
	url := f.gcrURL + "maven-central/" + itemName
	resp, err := httpGet(ctx, f.client, url)
	if err != nil {
		return "", xerrors.Errorf("http get error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// These are cases when version dir contains link to sha1 file
	// But file doesn't exist
	// e.g. https://repo.maven.apache.org/maven2/com/adobe/aem/uber-jar/6.4.8.2/uber-jar-6.4.8.2-sources.jar.sha1
	if resp.StatusCode == http.StatusNotFound {
		return "", nil // TODO add special error for this
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", xerrors.Errorf("can't read sha1 %s: %w", url, err)
	}

	// there are empty xxx.jar.sha1 files. Skip them.
	// e.g. https://repo.maven.apache.org/maven2/org/wso2/msf4j/msf4j-swagger/2.5.2/msf4j-swagger-2.5.2.jar.sha1
	// https://repo.maven.apache.org/maven2/org/wso2/carbon/analytics/org.wso2.carbon.permissions.rest.api/2.0.248/org.wso2.carbon.permissions.rest.api-2.0.248.jar.sha1
	if len(data) == 0 {
		return "", nil
	}

	// Validate SHA1 as there are xxx.jar.sha1 files with additional data.
	// e.g.
	//   https://repo.maven.apache.org/maven2/aspectj/aspectjrt/1.5.2a/aspectjrt-1.5.2a.jar.sha1
	//   https://repo.maven.apache.org/maven2/xerces/xercesImpl/2.9.0/xercesImpl-2.9.0.jar.sha1
	sha1, found := lo.Find(strings.Split(strings.TrimSpace(string(data)), " "), func(s string) bool {
		if _, err = hex.DecodeString(s); err != nil {
			return false
		}
		return len(s) == 40
	})
	if !found {
		f.wrongSHA1s = append(f.wrongSHA1s, fmt.Sprintf("%s (%s)", url, err))
		return "", nil
	}
	return sha1, nil
}

// Run processes records and writes them to appropriate shard files
func (a *Aggregator) Run(recordsCh <-chan Record) error {
	a.logger.Info("Starting record aggregator")

	// Close all writers and files when done
	defer a.closeWriters()

	for rec := range recordsCh {
		// Calculate shard index based on GroupID+ArtifactID
		shardIdx := int(hashGA(rec.GroupID, rec.ArtifactID) % uint64(a.shardCount))

		// Get or create writer for this shard
		writer, err := a.newWriter(shardIdx)
		if err != nil {
			a.logger.Error("Failed to get writer",
				slog.Int("shard", shardIdx),
				slog.Any("error", err))
			return xerrors.Errorf("failed to get writer: %w", err)
		}

		// Since versionDir is the same as version in most cases, we can exclude it from the record for saving space.
		if rec.VersionDir == rec.Version {
			rec.Version = "-"
		}

		// Write TSV record: GroupID, ArtifactID, Version, SHA1
		err = writer.Write([]string{
			rec.GroupID,
			rec.ArtifactID,
			rec.VersionDir,
			rec.Version,
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
		if a.recordsProcessed%10000 == 0 {
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

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(a.baseDir, 0755); err != nil {
		return nil, xerrors.Errorf("failed to create base directory: %w", err)
	}

	// Determine format string based on number of shards
	digits := digitsFor(a.shardCount)
	format := fmt.Sprintf("%%0%dx.tsv", digits)

	// Create or open the TSV file using dynamic hex format for shard index (append mode)
	outPath := filepath.Join(a.baseDir, fmt.Sprintf(format, shardIdx))
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

func httpGet(ctx context.Context, client *retryablehttp.Client, url string) (*http.Response, error) {
	// Sleep for a while to avoid 429 error
	randomSleep()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to create a HTTP request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http error (%s): %w", url, err)
	}
	return resp, nil
}

// parseItemName parses item name and returns groupID, artifactID, versionDir and version
func parseItemName(name string) (string, string, string, string) {
	name = strings.TrimPrefix(name, "maven2/")
	ss := strings.Split(name, "/")

	// There are cases when name is incorrect (e.g. name doesn't have artifactID)
	if len(ss) < 4 {
		return "", "", "", ""
	}
	groupID := strings.Join(ss[:len(ss)-3], ".")
	artifactID := ss[len(ss)-3]
	versionDir := ss[len(ss)-2]

	// Take version from filename as they are not always the same as in versionDir.
	// e.g.
	//   https://repo.maven.apache.org/maven2/ai/rapids/cudf/0.14/cudf-0.14.jar.sha1
	//   https://repo.maven.apache.org/maven2/ai/rapids/cudf/0.14/cudf-0.14-cuda10-1.jar.sha1
	version := strings.TrimSuffix(strings.TrimPrefix(ss[len(ss)-1], artifactID+"-"), ".jar.sha1")

	return groupID, artifactID, versionDir, version
}

func randomSleep() {
	// Seed rand
	r := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	time.Sleep(time.Duration(r.Float64() * float64(100*time.Millisecond)))
}

// Utility function: hash GroupId + ArtifactId for sharding
func hashGA(g, a string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(g))
	h.Write([]byte("|"))
	h.Write([]byte(a))
	return h.Sum64()
}

// Utility function: hash GroupId + ArtifactId + Version for deduplication
func hashGAV(g, a, v string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(g))
	h.Write([]byte("|"))
	h.Write([]byte(a))
	h.Write([]byte("|"))
	h.Write([]byte(v))
	return h.Sum64()
}
