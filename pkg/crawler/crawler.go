package crawler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

const mavenRepoURL = "https://repo.maven.apache.org/maven2/"

type Crawler struct {
	dir        string
	http       *retryablehttp.Client
	lastUpdate time.Time

	rootUrl         string
	wg              sync.WaitGroup
	urlCh           chan string
	limit           *semaphore.Weighted
	wrongSHA1Values []string
}

type Option struct {
	Limit      int64
	RootUrl    string
	CacheDir   string
	LastUpdate time.Time
}

func NewCrawler(opt Option) Crawler {
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

	if opt.RootUrl == "" {
		opt.RootUrl = mavenRepoURL
	}

	indexDir := filepath.Join(opt.CacheDir, "indexes")
	slog.Info("Index dir", slog.String("path", indexDir))

	return Crawler{
		dir:        indexDir,
		http:       client,
		lastUpdate: opt.LastUpdate,

		rootUrl: opt.RootUrl,
		urlCh:   make(chan string, opt.Limit*10),
		limit:   semaphore.NewWeighted(opt.Limit),
	}
}

func (c *Crawler) Crawl(ctx context.Context) error {
	slog.Info("Crawl maven repository and save indexes")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error)
	defer close(errCh)

	// Add a root url
	c.urlCh <- c.rootUrl
	c.wg.Add(1)

	go func() {
		c.wg.Wait()
		close(c.urlCh)
	}()

	crawlDone := make(chan struct{})

	// For the HTTP loop
	go func() {
		defer func() { crawlDone <- struct{}{} }()

		var count int
		for url := range c.urlCh {
			count++
			if count%1000 == 0 {
				slog.Info("Indexed digests", slog.Int("count", count))
			}
			if err := c.limit.Acquire(ctx, 1); err != nil {
				errCh <- xerrors.Errorf("semaphore acquire error: %w", err)
				return
			}
			go func(url string) {
				defer c.limit.Release(1)
				defer c.wg.Done()
				if err := c.Visit(ctx, url); err != nil {
					select {
					// Context can be canceled if we receive an error from another Visit function.
					case <-ctx.Done():
						return
					case errCh <- err:
						return
					}
				}
			}(url)
		}
	}()

loop:
	for {
		select {
		// Wait for DB update to complete
		case <-crawlDone:
			break loop
		case err := <-errCh:
			cancel() // Stop all running Visit functions to avoid writing to closed c.urlCh.
			close(c.urlCh)
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

func (c *Crawler) Visit(ctx context.Context, url string) error {
	resp, err := c.httpGet(ctx, url)
	if err != nil {
		return xerrors.Errorf("http get error: %w", err)
	}
	defer resp.Body.Close()

	// There are cases when url doesn't exist
	// e.g. https://repo.maven.apache.org/maven2/io/springboot/ai/spring-ai-anthropic/
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	var children []string
	var foundMetadata bool
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := linkFromSelection(selection)
		if link == "maven-metadata.xml" {
			foundMetadata = true
			return
		} else if link == "../" || !strings.HasSuffix(link, "/") {
			// only `../` and dirs have `/` suffix. We don't need to check other files.
			return
		}
		if !c.skipChildLink(selection) {
			children = append(children, link)
		}

	})

	if foundMetadata {
		meta, err := c.parseMetadata(ctx, url+"maven-metadata.xml")
		if err != nil {
			return xerrors.Errorf("metadata parse error: %w", err)
		}
		if meta != nil {
			if err = c.crawlSHA1(ctx, url, meta, children); err != nil {
				return err
			}
			// Return here since there is no need to crawl dirs anymore.
			return nil
		}
	}

	c.wg.Add(len(children))

	go func() {
		for _, child := range children {
			select {
			// Context can be canceled if we receive an error from another Visit function.
			case <-ctx.Done():
				return
			case c.urlCh <- url + child:
				continue
			}
		}
	}()

	return nil
}

func (c *Crawler) skipChildLink(selection *goquery.Selection) bool {
	if c.lastUpdate.IsZero() {
		return false
	}

	fields := strings.Fields(selection.Get(0).NextSibling.Data)
	if len(fields) == 0 || fields[0] == "-" {
		return false
	}
	linkTime, err := time.Parse("2006-01-02", fields[0])
	if err != nil {
		slog.Warn("Unable to parse link time", slog.String("time", fields[0]))
		return false
	}

	return linkTime.Before(c.lastUpdate)
}

func (c *Crawler) crawlSHA1(ctx context.Context, baseURL string, meta *Metadata, dirs []string) error {
	var foundVersions []Version
	// Check each version dir to find links to `*.jar.sha1` files.
	for _, dir := range dirs {
		dirURL := baseURL + dir
		sha1Urls, err := c.sha1Urls(ctx, dirURL)
		if err != nil {
			return xerrors.Errorf("unable to get list of sha1 files from %q: %s", dirURL, err)
		}

		// Remove the `/` suffix to correctly compare file versions with version from directory name.
		dirVersion := strings.TrimSuffix(dir, "/")
		var dirVersionSha1 []byte
		var versions []Version
		for _, sha1Url := range sha1Urls {
			sha1, err := c.fetchSHA1(ctx, sha1Url)
			if err != nil {
				return xerrors.Errorf("unable to fetch sha1: %s", err)
			}
			if ver := versionFromSha1URL(meta.ArtifactID, sha1Url); ver != "" && len(sha1) != 0 {
				// Save sha1 for the file where the version is equal to the version from the directory name in order to remove duplicates later
				// Avoid overwriting dirVersion when inserting versions into the database (sha1 is uniq blob)
				// e.g. `cudf-0.14-cuda10-1.jar.sha1` should not overwrite `cudf-0.14.jar.sha1`
				// https://repo.maven.apache.org/maven2/ai/rapids/cudf/0.14/
				if ver == dirVersion {
					dirVersionSha1 = sha1
				} else {
					versions = append(versions, Version{
						Version: ver,
						SHA1:    sha1,
					})
				}
			}
		}
		// Remove duplicates of dirVersionSha1
		versions = lo.Filter(versions, func(v Version, _ int) bool {
			return !bytes.Equal(v.SHA1, dirVersionSha1)
		})

		if dirVersionSha1 != nil {
			versions = append(versions, Version{
				Version: dirVersion,
				SHA1:    dirVersionSha1,
			})
		}

		foundVersions = append(foundVersions, versions...)
	}

	if len(foundVersions) == 0 {
		return nil
	}

	index := &Index{
		GroupID:     meta.GroupID,
		ArtifactID:  meta.ArtifactID,
		Versions:    foundVersions,
		ArchiveType: types.JarType,
	}
	fileName := fmt.Sprintf("%s.json", index.ArtifactID)
	filePath := filepath.Join(c.dir, index.GroupID, fileName)
	if err := fileutil.WriteJSON(filePath, index); err != nil {
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

func (c *Crawler) parseMetadata(ctx context.Context, url string) (*Metadata, error) {
	// We need to skip metadata.xml files from groupID folder
	// e.g. https://repo.maven.apache.org/maven2/args4j/maven-metadata.xml
	if len(strings.Split(url, "/")) < 7 {
		return nil, nil
	}

	resp, err := c.httpGet(ctx, url)
	if err != nil {
		return nil, xerrors.Errorf("http get error: %w", err)
	}
	defer resp.Body.Close()

	// There are cases when metadata.xml file doesn't exist
	// e.g. https://repo.maven.apache.org/maven2/io/springboot/ai/spring-ai-vertex-ai-gemini-spring-boot-starter/maven-metadata.xml
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var meta Metadata
	if err = xml.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, xerrors.Errorf("%s decode error: %w", url, err)
	}
	// Skip metadata without `GroupID` and ArtifactID` fields
	// e.g. https://repo.maven.apache.org/maven2/at/molindo/maven-metadata.xml
	if meta.ArtifactID == "" || meta.GroupID == "" {
		return nil, nil
	}

	// we don't need metadata.xml files from version folder
	// e.g. https://repo.maven.apache.org/maven2/HTTPClient/HTTPClient/0.3-3/maven-metadata.xml
	if len(meta.Versioning.Versions) == 0 {
		return nil, nil
	}
	return &meta, nil
}

func (c *Crawler) fetchSHA1(ctx context.Context, url string) ([]byte, error) {
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

func randomSleep() {
	// Seed rand
	r := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	time.Sleep(time.Duration(r.Float64() * float64(100*time.Millisecond)))
}

func versionFromSha1URL(artifactId, sha1URL string) string {
	ss := strings.Split(sha1URL, "/")
	fileName := ss[len(ss)-1]
	if !strings.HasPrefix(fileName, artifactId) {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(fileName, artifactId+"-"), ".jar.sha1")
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
