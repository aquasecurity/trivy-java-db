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
	"strings"
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

type Crawler struct {
	dir  string
	http *retryablehttp.Client

	gcrURL string

	limit           int
	wrongSHA1Values []string
}

type Option struct {
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

	return Crawler{
		dir:  opt.IndexDir,
		http: client,

		gcrURL: opt.GcsURL,
		limit:  opt.Limit,
	}, nil
}

func (c *Crawler) Crawl(ctx context.Context) error {
	slog.Info("Crawl GCS and save indexes")
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(c.limit)

	// Get all item names suffixing with .jar.sha1 from GCS
	itemCh := make(chan string)
	g.Go(func() error {
		defer close(itemCh)
		return c.crawlGCSItems(ctx, itemCh)
	})

	// Crawl each item and save the index
	for item := range itemCh {
		g.Go(func() error {
			return c.crawlSHA1(ctx, item)
		})
	}

	// Check whether any of the goroutines failed. Since g is accumulating the
	// errors, we don't need to send them (or check for them) in the individual
	// results sent on the channel.
	if err := g.Wait(); err != nil {
		return err
	}

	slog.Info("Crawl completed")
	if len(c.wrongSHA1Values) > 0 {
		for _, wrongSHA1 := range c.wrongSHA1Values {
			slog.Warn("Wrong SHA1 file", slog.String("error", wrongSHA1))
		}
	}
	return nil
}

func (c *Crawler) crawlGCSItems(ctx context.Context, itemCh chan string) error {
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

	var count int
	for {
		r, err := c.fetchItems(ctx, req)
		if err != nil {
			return xerrors.Errorf("unable to get items: %w", err)
		}
		for _, item := range r.Items {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case itemCh <- item.Name:
			}

			count++
			if count%100000 == 0 {
				slog.Info(fmt.Sprintf("Crawled %d artifacts", count))
			}
		}

		if r.NextPageToken == "" {
			break
		}
		query.Set("pageToken", r.NextPageToken)
		req.URL.RawQuery = query.Encode()

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

func (c *Crawler) crawlSHA1(ctx context.Context, item string) error {
	// Don't include sources, test, javadocs, scaladoc files
	if strings.HasSuffix(item, "sources.jar.sha1") ||
		strings.HasSuffix(item, "test.jar.sha1") || strings.HasSuffix(item, "tests.jar.sha1") ||
		strings.HasSuffix(item, "javadoc.jar.sha1") || strings.HasSuffix(item, "scaladoc.jar.sha1") {
		return nil
	}

	groupID, artifactID, versionDir, version := parseItemName(item)
	if groupID == "" || artifactID == "" {
		return nil
	}

	filePathElements := []string{c.dir}
	filePathElements = append(filePathElements, strings.Split(groupID, ".")...) // Convert group-id to directory names
	filePathElements = append(filePathElements, artifactID, versionDir, fmt.Sprintf("%s.json", version))
	filePath := filepath.Join(filePathElements...)

	// If the file already exists, skip the crawl
	if fileutil.Exists(filePath) {
		return nil
	}

	sha1, err := c.fetchSHA1(ctx, item)
	if err != nil {
		return xerrors.Errorf("unable to fetch sha1: %s", err)
	} else if sha1 == "" {
		return nil
	}

	index := Index{
		SHA1: sha1,
		// TODO: Add license
	}
	if err := fileutil.WriteJSON(filePath, index); err != nil {
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
