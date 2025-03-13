package crawler

import (
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
	"golang.org/x/net/html/charset"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

const (
	mavenRepoURL = "https://repo.maven.apache.org/maven2/"
	gcrURL       = "https://storage.googleapis.com/maven-central/maven2/"
)

type Crawler struct {
	dir  string
	http *retryablehttp.Client

	mavenUrl        string
	gcrUrl          string
	wg              sync.WaitGroup
	urlCh           chan string
	limit           *semaphore.Weighted
	wrongSHA1Values []string
	wrongPomFiles   []string
}

type Option struct {
	Limit    int64
	MavenUrl string
	GcrUrl   string
	CacheDir string
}

func NewCrawler(opt Option) (Crawler, error) {
	client := retryablehttp.NewClient()
	client.RetryMax = 10
	client.Logger = slog.Default()
	client.RetryWaitMin = 1 * time.Minute
	client.RetryWaitMax = 5 * time.Minute
	client.Backoff = retryablehttp.LinearJitterBackoff
	client.ResponseLogHook = func(_ retryablehttp.Logger, resp *http.Response) {
		// GCR doesn't have all the files sha1.
		// cf. https://github.com/aquasecurity/trivy-java-db/pull/52#issuecomment-2703694693
		// We get sha1 for these files from maven-central.
		// So we need to disable warnings for these files to avoid noise.
		if resp.StatusCode == http.StatusNotFound && strings.HasPrefix(resp.Request.URL.String(), gcrURL) {
			return
		}

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

	if opt.GcrUrl == "" {
		opt.GcrUrl = gcrURL
	}

	indexDir := filepath.Join(opt.CacheDir, "indexes")
	slog.Info("Index dir", slog.String("path", indexDir))

	return Crawler{
		dir:  indexDir,
		http: client,

		mavenUrl: opt.MavenUrl,
		gcrUrl:   opt.GcrUrl,
		urlCh:    make(chan string, opt.Limit*10),
		limit:    semaphore.NewWeighted(opt.Limit),
	}, nil
}

func (c *Crawler) Crawl(ctx context.Context) error {
	slog.Info("Crawl maven repository and save indexes")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error)
	defer close(errCh)

	// Add a root url
	c.urlCh <- c.mavenUrl
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
	if len(c.wrongPomFiles) > 0 {
		for _, wrongPomFile := range c.wrongPomFiles {
			slog.Warn("Wrong pom file", slog.String("error", wrongPomFile))
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
		children = append(children, link)
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

func (c *Crawler) crawlSHA1(ctx context.Context, baseURL string, meta *Metadata, dirs []string) error {
	fileName := fmt.Sprintf("%s.json", meta.ArtifactID)
	dirPath := filepath.Join(strings.Split(meta.GroupID, ".")...)
	filePath := filepath.Join(c.dir, dirPath, fileName)

	var versions []types.Version
	savedVersions, err := c.getSavedVersions(filePath)
	if err == nil {
		versions = savedVersions
	}

	// Check each version dir to find links to `*.jar.sha1` files.
	for _, dir := range dirs {
		dir = strings.TrimSuffix(dir, "/")
		sha1Urls, pomUrl, err := c.requiredFilesUrls(ctx, baseURL, dir)
		if err != nil {
			return xerrors.Errorf("unable to get list of sha1 files from %q: %s", baseURL+dir, err)
		}

		dirVersion := types.Version{
			Version: dir,
		}

		var versionsFromDir []types.Version
		for _, sha1Url := range sha1Urls {
			ver := versionFromSha1URL(meta.ArtifactID, sha1Url)

			// Skip check version, if indexes already contain this version
			if slices.ContainsFunc(versions, func(v types.Version) bool {
				return v.Version == ver
			}) {
				continue
			}

			sha1, err := c.fetchSHA1(ctx, sha1Url)
			if err != nil {
				return xerrors.Errorf("unable to fetch sha1: %s", err)
			}

			// Save sha1 for the file where the version is equal to the version from the directory name in order to remove duplicates later
			// Avoid overwriting dirVersion when inserting versions into the database (sha1 is uniq blob)
			// e.g. `cudf-0.14-cuda10-1.jar.sha1` should not overwrite `cudf-0.14.jar.sha1`
			// https://repo.maven.apache.org/maven2/ai/rapids/cudf/0.14/
			if ver == dirVersion.Version {
				dirVersion.SHA1 = sha1

				// Save licenses for dir version
				if pomUrl != "" {
					ll, err := c.licenses(ctx, pomUrl)
					if err != nil {
						c.wrongPomFiles = append(c.wrongPomFiles, fmt.Sprintf("%s (%s)", pomUrl, err))
					}

					if len(ll) > 0 {
						dirVersion.Licenses = ll
					}
				}
				continue
			}

			versionsFromDir = append(versionsFromDir, types.Version{
				Version: ver,
				SHA1:    sha1,
			})

		}

		if dirVersion.SHA1 != "" {
			// Remove duplicates of dirVersionSha1
			versionsFromDir = lo.Filter(versionsFromDir, func(v types.Version, _ int) bool {
				return v.SHA1 != dirVersion.SHA1
			})

			versionsFromDir = append(versionsFromDir, dirVersion)
		}

		versions = append(versions, versionsFromDir...)
	}

	if len(versions) == 0 || len(savedVersions) == len(versions) {
		return nil
	}

	slices.SortFunc(versions, func(a, b types.Version) int {
		return cmp.Compare(a.Version, b.Version)
	})

	if err = fileutil.WriteJSON(filePath, versions); err != nil {
		return xerrors.Errorf("json write error: %w", err)
	}
	return nil
}

func (c *Crawler) getSavedVersions(filePath string) ([]types.Version, error) {
	f, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, xerrors.Errorf("unable to index read file %s: %w", filePath, err)
	}

	var vers []types.Version
	if err = json.Unmarshal(f, &vers); err != nil {
		return nil, xerrors.Errorf("unable to unmarshal file %s: %w", filePath, err)
	}

	return vers, nil
}

// requiredFilesUrls returns urls for *.jar.sha1 and *.pom files
func (c *Crawler) requiredFilesUrls(ctx context.Context, baseURL, dir string) ([]string, string, error) {
	url := baseURL + dir + "/"
	resp, err := c.httpGet(ctx, url)
	if err != nil {
		return nil, "", xerrors.Errorf("http get error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, "", xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	// Version dir may contain multiple `*jar.sha1` files.
	// e.g. https://repo1.maven.org/maven2/org/jasypt/jasypt/1.9.3/
	// We need to take all links.
	var sha1URLs []string
	var pomUrl string
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := linkFromSelection(selection)
		fullLink := url + link
		if strings.HasSuffix(link, dir+".pom") {
			pomUrl = fullLink
			return
		}

		// Don't include sources, test, javadocs, scaladoc files
		if strings.HasSuffix(link, ".jar.sha1") && !strings.HasSuffix(link, "sources.jar.sha1") &&
			!strings.HasSuffix(link, "test.jar.sha1") && !strings.HasSuffix(link, "tests.jar.sha1") &&
			!strings.HasSuffix(link, "javadoc.jar.sha1") && !strings.HasSuffix(link, "scaladoc.jar.sha1") {
			sha1URLs = append(sha1URLs, fullLink)
		}
	})
	return sha1URLs, pomUrl, nil
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

func (c *Crawler) fetchSHA1(ctx context.Context, url string) (string, error) {
	resp, err := c.tryGetFile(ctx, url)
	if err != nil {
		return "", xerrors.Errorf("unable to get file: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// These are cases when version dir contains link to sha1 file
	// But file doesn't exist
	// e.g. https://repo.maven.apache.org/maven2/com/adobe/aem/uber-jar/6.4.8.2/uber-jar-6.4.8.2-sources.jar.sha1
	if resp.StatusCode == http.StatusNotFound {
		return "", nil // TODO add special error for this
	}

	sha1, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", xerrors.Errorf("can't read sha1 %s: %w", url, err)
	}

	// there are empty xxx.jar.sha1 files. Skip them.
	// e.g. https://repo.maven.apache.org/maven2/org/wso2/msf4j/msf4j-swagger/2.5.2/msf4j-swagger-2.5.2.jar.sha1
	// https://repo.maven.apache.org/maven2/org/wso2/carbon/analytics/org.wso2.carbon.permissions.rest.api/2.0.248/org.wso2.carbon.permissions.rest.api-2.0.248.jar.sha1
	if len(sha1) == 0 {
		return "", nil
	}
	// there are xxx.jar.sha1 files with additional data. e.g.:
	// https://repo.maven.apache.org/maven2/aspectj/aspectjrt/1.5.2a/aspectjrt-1.5.2a.jar.sha1
	// https://repo.maven.apache.org/maven2/xerces/xercesImpl/2.9.0/xercesImpl-2.9.0.jar.sha1
	var sha1s string
	for _, s := range strings.Split(strings.TrimSpace(string(sha1)), " ") {
		if _, err = hex.DecodeString(s); err == nil {
			sha1s = s
			break
		}
	}
	if sha1s == "" {
		c.wrongSHA1Values = append(c.wrongSHA1Values, fmt.Sprintf("%s (%s)", url, err))
		return "", nil
	}

	// We need to decode sha1 to find sha1.
	// But we need to keep default
	// cf.
	return sha1s, nil
}

func (c *Crawler) tryGetFile(ctx context.Context, url string) (*http.Response, error) {
	gcsURL := strings.ReplaceAll(url, c.mavenUrl, c.gcrUrl)
	resp, err := c.httpGet(ctx, gcsURL)
	if err != nil {
		return nil, xerrors.Errorf("http get error: %w", err)
	} else if resp.StatusCode == http.StatusOK {
		return resp, nil
	}

	resp, err = c.httpGet(ctx, url)
	if err != nil {
		return nil, xerrors.Errorf("http get error: %w", err)
	}

	return resp, nil
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

func (c *Crawler) licenses(ctx context.Context, url string) ([]string, error) {
	resp, err := c.tryGetFile(ctx, url)
	if err != nil {
		return nil, xerrors.Errorf("unable to get file: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var pom pomXML
	decoder := xml.NewDecoder(resp.Body)
	decoder.CharsetReader = charset.NewReaderLabel

	if err = decoder.Decode(&pom); err != nil {
		return nil, xerrors.Errorf("unable to decode pom file: %w", err)
	}

	licenses := lo.Map(pom.Licenses, func(license pomLicense, _ int) string {
		return license.Name
	})
	return licenses, nil
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
