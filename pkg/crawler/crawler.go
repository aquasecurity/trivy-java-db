package crawler

import (
	"bytes"
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

const (
	mavenRepoURL = "https://repo.maven.apache.org/maven2/"
	gcsRepoURL   = "https://storage.googleapis.com/maven-central/"
	gcsApiURL    = "https://storage.googleapis.com/storage/v1/b/maven-central/o/"
)

type Crawler struct {
	dir  string
	http *retryablehttp.Client
	dbc  *db.DB

	mavenRepoURL string
	gcrRepoURL   string
	gcsApiURL    string

	wg              sync.WaitGroup
	limit           *semaphore.Weighted
	errCh           chan error
	wrongSHA1Values []string

	count int64
}

type Option struct {
	Limit      int64
	MavenUrl   string
	GcsRepoUrl string
	GcsApiUrl  string
	CacheDir   string
}

func NewCrawler(opt Option) (Crawler, error) {
	client := retryablehttp.NewClient()
	client.RetryMax = 10
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

	if opt.MavenUrl == "" {
		opt.MavenUrl = mavenRepoURL
	}

	if opt.GcsApiUrl == "" {
		opt.GcsApiUrl = gcsApiURL
	}

	if opt.GcsRepoUrl == "" {
		opt.GcsRepoUrl = gcsRepoURL
	}

	indexDir := filepath.Join(opt.CacheDir, "indexes")
	slog.Info("Index dir", slog.String("path", indexDir))

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
		dir:   indexDir,
		http:  client,
		dbc:   &dbc,
		errCh: make(chan error),

		mavenRepoURL: opt.MavenUrl,
		gcrRepoURL:   opt.GcsRepoUrl,
		gcsApiURL:    opt.GcsApiUrl,
		limit:        semaphore.NewWeighted(opt.Limit),
	}, nil
}

func (c *Crawler) Crawl(ctx context.Context) error {
	slog.Info("Crawl maven repository and save indexes")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	rootDirs, err := c.rootDirs(ctx)
	if err != nil {
		return xerrors.Errorf("unable to get root dirs: %w", err)
	}

	c.wg.Add(1)
	crawlDone := make(chan struct{})

	go func() {
		c.wg.Wait()
		close(c.errCh)
		crawlDone <- struct{}{}
	}()

	// Check all root dirs
	go func() {
		for _, rootDir := range rootDirs {
			if err = c.limit.Acquire(ctx, 1); err != nil {
				c.errCh <- xerrors.Errorf("semaphore acquire error: %w", err)
				return
			}

			go func(rootDir string) {
				defer c.limit.Release(1)
				defer c.wg.Done()
				c.wg.Add(1)
				if err = c.crawlRootDir(ctx, rootDir); err != nil {
					select {
					// Context can be canceled if we receive an error from another crawlRootDir function.
					case <-ctx.Done():
						return
					case c.errCh <- err:
						return
					}
				}
			}(rootDir)
		}

		c.wg.Done() // Close first WG
	}()

loop:
	for {
		select {
		// Wait for DB update to complete
		case <-crawlDone:
			break loop
		case err := <-c.errCh:
			cancel() // Stop all running crawlRootDir functions to avoid writing to closed c.urlCh.
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

func (c *Crawler) rootDirs(ctx context.Context) ([]string, error) {
	resp, err := c.httpGet(ctx, c.mavenRepoURL)
	if err != nil {
		return nil, xerrors.Errorf("http get error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("unable to get root URL: %s", resp.Status)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	var rootDirs []string
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := linkFromSelection(selection)
		if link == "../" || !strings.HasSuffix(link, "/") {
			// only `../` and dirs have `/` suffix. We don't need to check other files.
			return
		}
		rootDirs = append(rootDirs, link)
	})

	return rootDirs, nil
}

func (c *Crawler) crawlRootDir(ctx context.Context, rootDir string) error {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, c.gcsApiURL, nil)
	if err != nil {
		return xerrors.Errorf("unable to create a HTTP request: %w", err)
	}

	query := req.URL.Query()
	query.Set("prefix", "maven2/"+rootDir)
	query.Set("matchGlob", "**/*.jar.sha1")
	query.Set("maxResults", "5000")
	req.URL.RawQuery = query.Encode()

	var items []string
	for {
		r, err := c.rootDirObjects(ctx, req)
		if err != nil {
			return xerrors.Errorf("unable to get root dir objects: %w", err)
		}
		query.Set("pageToken", r.NextPageToken)
		req.URL.RawQuery = query.Encode()
		items = append(items, lo.Map(r.Items, func(item Item, _ int) string {
			return item.Name
		})...)

		if r.NextPageToken == "" {
			break
		}

	}

	err = c.parseItems(ctx, items)
	if err != nil {
		return xerrors.Errorf("unable to parse API response: %w", err)
	}

	return nil
}

func (c *Crawler) rootDirObjects(ctx context.Context, req *retryablehttp.Request) (gcsApiResponse, error) {
	resp, err := c.httpGet(ctx, req.URL.String())
	if err != nil {
		return gcsApiResponse{}, xerrors.Errorf("http error (%s): %w", req.URL.String(), err)
	}
	defer resp.Body.Close()

	r := gcsApiResponse{}

	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		return gcsApiResponse{}, xerrors.Errorf("unable to parse API response: %w", err)
	}

	return r, nil
}

func (c *Crawler) parseItems(ctx context.Context, items []string) error {
	var prevGroupID, prevArtifactID string
	itemsByVersionDir := map[string][]string{}
	for _, itemName := range items {
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
					//return xerrors.Errorf("unable to crawl SHA1: %w", err)
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

func (c *Crawler) crawlSHA1(ctx context.Context, groupID, artifactID string, dirs map[string][]string) error {
	if groupID == "" || artifactID == "" {
		return nil
	}

	atomic.AddInt64(&c.count, 1)
	if c.count%1000 == 0 {
		slog.Info(fmt.Sprintf("Crawled %d artifacts", atomic.LoadInt64(&c.count)))
	}

	var foundVersions []types.Version
	// Get versions from the DB (if exists) to reduce the number of requests to the server
	savedVersion, err := c.versionsFromDB(groupID, artifactID)
	if err != nil {
		return xerrors.Errorf("unable to get list of versions from DB: %w", err)
	}
	// Check each version dir to find links to `*.jar.sha1` files.
	for dirVersion, itemNames := range dirs {
		var dirVersionSha1 []byte
		var versions []types.Version

		for _, itemName := range itemNames {
			_, _, _, ver := parseItemName(itemName)
			sha1, ok := savedVersion[ver]
			if !ok {
				sha1, err = c.fetchSHA1(ctx, itemName)
				if err != nil {
					return xerrors.Errorf("unable to fetch sha1: %s", err)
				}
			}
			// Save sha1 for the file where the version is equal to the version from the directory name in order to remove duplicates later
			// Avoid overwriting dirVersion when inserting versions into the database (sha1 is uniq blob)
			// e.g. `cudf-0.14-cuda10-1.jar.sha1` should not overwrite `cudf-0.14.jar.sha1`
			// https://repo.maven.apache.org/maven2/ai/rapids/cudf/0.14/
			if ver == dirVersion {
				dirVersionSha1 = sha1
			} else {
				versions = append(versions, types.Version{
					Version: ver,
					SHA1:    sha1,
				})
			}
		}
		// Remove duplicates of dirVersionSha1
		versions = lo.Filter(versions, func(v types.Version, _ int) bool {
			return !bytes.Equal(v.SHA1, dirVersionSha1)
		})

		if dirVersionSha1 != nil {
			versions = append(versions, types.Version{
				Version: dirVersion,
				SHA1:    dirVersionSha1,
			})
		}

		versions = lo.Filter(versions, func(v types.Version, _ int) bool {
			_, ok := savedVersion[v.Version]
			return !ok
		})

		foundVersions = append(foundVersions, versions...)
	}

	if len(foundVersions) == 0 {
		return nil
	}

	index := &Index{
		GroupID:     groupID,
		ArtifactID:  artifactID,
		Versions:    foundVersions,
		ArchiveType: types.JarType,
	}
	fileName := fmt.Sprintf("%s.json", index.ArtifactID)
	filePath := filepath.Join(c.dir, index.GroupID, fileName)
	if err = fileutil.WriteJSON(filePath, index); err != nil {
		return xerrors.Errorf("json write error: %w", err)
	}
	return nil
}

func (c *Crawler) sha1Urls(ctx context.Context, url string) ([]string, error) {
	resp, err := c.httpGet(ctx, url)
	if err != nil {
		return nil, xerrors.Errorf("http get error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	// Version dir may contain multiple `*jar.sha1` files.
	// e.g. https://repo1.maven.org/maven2/org/jasypt/jasypt/1.9.3/
	// We need to take all links.
	var sha1URLs []string
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := linkFromSelection(selection)
		// Don't include sources, test, javadocs, scaladoc files
		if strings.HasSuffix(link, ".jar.sha1") && !strings.HasSuffix(link, "sources.jar.sha1") &&
			!strings.HasSuffix(link, "test.jar.sha1") && !strings.HasSuffix(link, "tests.jar.sha1") &&
			!strings.HasSuffix(link, "javadoc.jar.sha1") && !strings.HasSuffix(link, "scaladoc.jar.sha1") {
			sha1URLs = append(sha1URLs, url+link)
		}
	})
	return sha1URLs, nil
}

func (c *Crawler) fetchSHA1(ctx context.Context, itemName string) ([]byte, error) {
	url := c.gcrRepoURL + itemName
	resp, err := c.httpGet(ctx, url)
	if err != nil {
		return nil, xerrors.Errorf("http get error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// These are cases when version dir contains link to sha1 file
	// But file doesn't exist
	// e.g. https://repo.maven.apache.org/maven2/com/adobe/aem/uber-jar/6.4.8.2/uber-jar-6.4.8.2-sources.jar.sha1
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // TODO add special error for this
	}

	sha1, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("can't read sha1 %s: %w", url, err)
	}

	// there are empty xxx.jar.sha1 files. Skip them.
	// e.g. https://repo.maven.apache.org/maven2/org/wso2/msf4j/msf4j-swagger/2.5.2/msf4j-swagger-2.5.2.jar.sha1
	// https://repo.maven.apache.org/maven2/org/wso2/carbon/analytics/org.wso2.carbon.permissions.rest.api/2.0.248/org.wso2.carbon.permissions.rest.api-2.0.248.jar.sha1
	if len(sha1) == 0 {
		return nil, nil
	}
	// there are xxx.jar.sha1 files with additional data. e.g.:
	// https://repo.maven.apache.org/maven2/aspectj/aspectjrt/1.5.2a/aspectjrt-1.5.2a.jar.sha1
	// https://repo.maven.apache.org/maven2/xerces/xercesImpl/2.9.0/xercesImpl-2.9.0.jar.sha1
	var sha1b []byte
	for _, s := range strings.Split(strings.TrimSpace(string(sha1)), " ") {
		sha1b, err = hex.DecodeString(s)
		if err == nil {
			break
		}
	}
	if len(sha1b) == 0 {
		c.wrongSHA1Values = append(c.wrongSHA1Values, fmt.Sprintf("%s (%s)", url, err))
		return nil, nil
	}
	return sha1b, nil
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

func (c *Crawler) versionsFromDB(groupID, artifactID string) (map[string][]byte, error) {
	if c.dbc == nil {
		return nil, nil
	}
	return c.dbc.SelectVersionsByArtifactIDAndGroupID(artifactID, groupID)
}

func randomSleep() {
	// Seed rand
	r := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	time.Sleep(time.Duration(r.Float64() * float64(100*time.Millisecond)))
}

// linkFromSelection returns the link from goquery.Selection.
// There are times when maven breaks `text` - it removes part of the `text` and adds the suffix `...` (`.../` for dirs).
// e.g. `<a href="v1.1.0-226-g847ecff2d8e26f249422247d7665fe15f07b1744/">v1.1.0-226-g847ecff2d8e26f249422247d7665fe15.../</a>`
// In this case we should take `href`.
// But we don't need to get `href` if the text isn't broken.
// To avoid checking unnecessary links.
// e.g. `<pre id="contents"><a href="https://repo.maven.apache.org/maven2/abbot/">../</a>`
func linkFromSelection(selection *goquery.Selection) string {
	link := selection.Text()
	// maven uses `.../` suffix for dirs and `...` suffix for files.
	if href, ok := selection.Attr("href"); ok && (strings.HasSuffix(link, ".../") || (strings.HasSuffix(link, "..."))) {
		link = href
	}
	return link
}
