package crawler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

const (
	gcsURL = "https://storage.googleapis.com/"
)

type Crawler struct {
	dir  string
	http *retryablehttp.Client
	dbc  *db.DB

	gcrURL string

	wg              sync.WaitGroup
	limit           *semaphore.Weighted
	itemCh          chan string
	wrongSHA1Values []string

	count int64
}

type Option struct {
	Limit        int64
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

	var dbc db.DB
	dbDir := db.Dir(opt.CacheDir)
	if db.Exists(dbDir) {
		var err error
		dbc, err = db.New(dbDir)
		if err != nil {
			return Crawler{}, xerrors.Errorf("unable to open DB: %w", err)
		}
		slog.Info("DB is used for crawler", slog.String("path", opt.CacheDir))
	}

	return Crawler{
		dir:    opt.IndexDir,
		http:   client,
		dbc:    &dbc,
		itemCh: make(chan string),

		gcrURL: opt.GcsURL,
		limit:  semaphore.NewWeighted(opt.Limit),
	}, nil
}

func (c *Crawler) Crawl(ctx context.Context) error {
	slog.Info("Crawl GCS and save indexes")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	crawlDone := make(chan struct{})
	errCh := make(chan error)
	c.wg.Add(1)

	go func() {
		c.wg.Wait()
		crawlDone <- struct{}{}
	}()

	go func() {
		defer close(c.itemCh)
		defer c.wg.Done()
		err := c.crawlGCSItems(ctx)
		if err != nil {
			errCh <- err
		}
	}()

	go func() {
		c.wg.Add(1)
		defer c.wg.Done()

		err := c.parseItems(ctx)
		if err != nil {
			errCh <- err
		}
	}()

loop:
	for {
		select {
		case <-crawlDone:
			break loop
		case err := <-errCh:
			return err
		}
	}

	slog.Info("Crawl completed")
	if len(c.wrongSHA1Values) > 0 {
		for _, wrongSHA1 := range c.wrongSHA1Values {
			slog.Warn("Wrong SHA1 file", slog.String("error", wrongSHA1))
		}
	}
	return nil
}

func (c *Crawler) crawlGCSItems(ctx context.Context) error {
	url := c.gcrURL + "storage/v1/b/maven-central/o/"
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return xerrors.Errorf("unable to create a HTTP request: %w", err)
	}

	query := req.URL.Query()
	query.Set("prefix", "maven2/")
	query.Set("matchGlob", "**/*.jar.sha1")
	query.Set("maxResults", "5000")
	req.URL.RawQuery = query.Encode()

	for {
		r, err := c.fetchItems(ctx, req)
		if err != nil {
			return xerrors.Errorf("unable to get items: %w", err)
		}
		query.Set("pageToken", r.NextPageToken)
		req.URL.RawQuery = query.Encode()
		for _, item := range r.Items {
			c.itemCh <- item.Name
		}

		if r.NextPageToken == "" {
			break
		}

	}

	return nil
}

func (c *Crawler) fetchItems(ctx context.Context, req *retryablehttp.Request) (GcsApiResponse, error) {
	resp, err := c.httpGet(ctx, req.URL.String())
	if err != nil {
		return GcsApiResponse{}, xerrors.Errorf("http error (%s): %w", req.URL.String(), err)
	}
	defer resp.Body.Close()

	r := GcsApiResponse{}

	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		return GcsApiResponse{}, xerrors.Errorf("unable to parse API response: %w", err)
	}

	return r, nil
}

func (c *Crawler) parseItems(ctx context.Context) error {
	var prevGroupID, prevArtifactID string
	itemsByVersionDir := map[string][]string{}
	for itemName := range c.itemCh {
		// Don't include sources, test, javadocs, scaladoc files
		if strings.HasSuffix(itemName, "sources.jar.sha1") ||
			strings.HasSuffix(itemName, "test.jar.sha1") || strings.HasSuffix(itemName, "tests.jar.sha1") ||
			strings.HasSuffix(itemName, "javadoc.jar.sha1") || strings.HasSuffix(itemName, "scaladoc.jar.sha1") {
			continue
		}

		groupID, artifactID, versionDir, _ := parseItemName(itemName)
		if prevGroupID != groupID || prevArtifactID != artifactID {
			if err := c.limit.Acquire(ctx, 1); err != nil {
				return xerrors.Errorf("semaphore acquire error: %w", err)
			}
			go func(ctx context.Context, groupID, artifactID string, items map[string][]string) {
				defer c.limit.Release(1)
				defer c.wg.Done()
				c.wg.Add(1)
				err := c.crawlSHA1(ctx, groupID, artifactID, items)
				if err != nil {
					slog.Warn("crawlSHA1 failed", slog.String("error", err.Error()))
					return
				}
			}(ctx, prevGroupID, prevArtifactID, itemsByVersionDir)

			// Index saved in crawlSHA1
			// So we need to clear previous GAV
			prevGroupID = groupID
			prevArtifactID = artifactID
			itemsByVersionDir = map[string][]string{}
		}

		itemsByVersionDir[versionDir] = append(itemsByVersionDir[versionDir], itemName)
	}

	// Save last artifact
	err := c.crawlSHA1(ctx, prevGroupID, prevArtifactID, itemsByVersionDir)
	if err != nil {
		return xerrors.Errorf("unable to crawl SHA1: %w", err)
	}

	return nil
}

func (c *Crawler) crawlSHA1(ctx context.Context, groupID, artifactID string, dirs map[string][]string) error {
	if groupID == "" || artifactID == "" {
		return nil
	}

	atomic.AddInt64(&c.count, 1)
	if c.count%1000 == 0 {
		slog.Info(fmt.Sprintf("Crawled %d artifacts", atomic.LoadInt64(&c.count)))
	}

	var foundVersions []types.Version
	// Check each version dir to find links to `*.jar.sha1` files.
	for _, itemNames := range dirs {
		for _, itemName := range itemNames {
			_, _, _, ver := parseItemName(itemName)
			sha1, err := c.fetchSHA1(ctx, itemName)
			if err != nil {
				return xerrors.Errorf("unable to fetch sha1: %s", err)
			}

			// Save sha1 for the file where the version is equal to the version from the directory name in order to remove duplicates later
			// Avoid overwriting dirVersion when inserting versions into the database (sha1 is uniq blob)
			// e.g. `cudf-0.14-cuda10-1.jar.sha1` should not overwrite `cudf-0.14.jar.sha1`
			// https://repo.maven.apache.org/maven2/ai/rapids/cudf/0.14/
			foundVersions = append(foundVersions, types.Version{
				Version: ver,
				SHA1:    sha1,
			})
		}
	}

	if len(foundVersions) == 0 {
		return nil
	}

	slices.SortFunc(foundVersions, func(a, b types.Version) int {
		return strings.Compare(a.Version, b.Version)
	})

	index := &Index{
		Versions:  foundVersions,
		Packaging: types.JarType,
	}
	filePath := []string{c.dir}
	filePath = append(filePath, strings.Split(groupID, ".")...) // Convert groupID to directory names
	filePath = append(filePath, artifactID, fmt.Sprintf("%s.json", artifactID))
	if err := fileutil.WriteJSON(filepath.Join(filePath...), index); err != nil {
		return xerrors.Errorf("json write error: %w", err)
	}
	return nil
}

func (c *Crawler) fetchSHA1(ctx context.Context, itemName string) (string, error) {
	url := c.gcrURL + "maven-central/" + itemName
	resp, err := c.httpGet(ctx, url)
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
		c.wrongSHA1Values = append(c.wrongSHA1Values, fmt.Sprintf("%s (%s)", url, err))
		return "", nil
	}
	return sha1, nil
}

func (c *Crawler) httpGet(ctx context.Context, url string) (*http.Response, error) {
	// Sleep for a while to avoid 429 error
	randomSleep()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to create a HTTP request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http error (%s): %w", url, err)
	}
	return resp, nil
}

// parseItemName parses item name and returns groupID, artifactID and version
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
	// Take version from filename
	version := strings.TrimSuffix(strings.TrimPrefix(ss[len(ss)-1], artifactID+"-"), ".jar.sha1")
	return groupID, artifactID, versionDir, version

}

func randomSleep() {
	// Seed rand
	r := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	time.Sleep(time.Duration(r.Float64() * float64(100*time.Millisecond)))
}
