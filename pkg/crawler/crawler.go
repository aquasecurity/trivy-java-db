package crawler

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"
)

const mavenRepoURL = "https://repo.maven.apache.org/maven2/"

type Crawler struct {
	dir  string
	http *retryablehttp.Client

	rootUrl         string
	wg              sync.WaitGroup
	urlCh           chan string
	limit           *semaphore.Weighted
	wrongSHA1Values []string
}

type Option struct {
	Limit    int64
	RootUrl  string
	CacheDir string
}

func NewCrawler(opt Option) Crawler {
	client := retryablehttp.NewClient()
	client.RetryMax = 10
	client.Logger = nil

	if opt.RootUrl == "" {
		opt.RootUrl = mavenRepoURL
	}

	indexDir := filepath.Join(opt.CacheDir, "indexes")
	log.Printf("Index dir %s", indexDir)

	return Crawler{
		dir:  indexDir,
		http: client,

		rootUrl: opt.RootUrl,
		urlCh:   make(chan string, opt.Limit*10),
		limit:   semaphore.NewWeighted(opt.Limit),
	}
}

func (c *Crawler) Crawl(ctx context.Context) error {
	log.Println("Crawl maven repository and save indexes")
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
				log.Printf("Count: %d", count)
			}
			if err := c.limit.Acquire(ctx, 1); err != nil {
				errCh <- xerrors.Errorf("semaphore acquire error: %w", err)
				return
			}
			go func(url string) {
				defer c.limit.Release(1)
				defer c.wg.Done()
				if err := c.Visit(ctx, url); err != nil {
					errCh <- xerrors.Errorf("visit error: %w", err)
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
	log.Println("Crawl completed")
	if len(c.wrongSHA1Values) > 0 {
		log.Println("Wrong sha1 files:")
		for _, wrongSHA1 := range c.wrongSHA1Values {
			log.Println(wrongSHA1)
		}
	}
	return nil
}

func (c *Crawler) Visit(ctx context.Context, url string) error {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return xerrors.Errorf("unable to new HTTP request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return xerrors.Errorf("http get error (%s): %w", url, err)
	}
	defer resp.Body.Close()

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	var children []string
	var foundMetadata bool
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := selection.Text()
		// Find `maven-metadata.xml` to get artifact URL and determine the ArtifactID and GroupID
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
			default:
				c.urlCh <- url + child
			}
		}
	}()

	return nil
}

func (c *Crawler) crawlSHA1(ctx context.Context, baseURL string, meta *Metadata, versionDirs []string) error {
	var sha1URLs []string
	// Check each version dir to find links to `*.jar.sha1` files.
	for _, versionDir := range versionDirs {
		versionDirURL := baseURL + versionDir
		urls, err := c.sha1Urls(ctx, versionDirURL)
		if err != nil {
			return xerrors.Errorf("unable to get list of sha1 files from %q: %s", versionDirURL, err)
		}
		sha1URLs = append(sha1URLs, urls...)
	}

	var versions []Version
	for _, sha1URL := range sha1URLs {
		sha1, err := c.fetchSHA1(ctx, sha1URL)
		if err != nil {
			return xerrors.Errorf("unable to fetch sha1: %s", err)
		}
		if len(sha1) != 0 {
			v := Version{
				Version: versionFromSha1URL(meta.ArtifactID, sha1URL),
				SHA1:    sha1,
			}
			versions = append(versions, v)
		}
	}

	if len(versions) == 0 {
		return nil
	}

	index := &Index{
		GroupID:     meta.GroupID,
		ArtifactID:  meta.ArtifactID,
		Versions:    versions,
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
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to new HTTP request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http get error (%s): %w", url, err)
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
		link := selection.Text()
		if strings.HasSuffix(link, ".jar.sha1") && !strings.HasSuffix(link, "sources.jar.sha1") &&
			!strings.HasSuffix(link, "test.jar.sha1") && !strings.HasSuffix(link, "javadoc.jar.sha1") {
			sha1URLs = append(sha1URLs, url+link)
		}
	})
	return sha1URLs, nil
}

func (c *Crawler) parseMetadata(ctx context.Context, url string) (*Metadata, error) {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to new HTTP request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http get error (%s): %w", url, err)
	}
	defer resp.Body.Close()

	var meta Metadata
	if err = xml.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, xerrors.Errorf("%s decode error: %w", url, err)
	}
	// we don't need metadata.xml files from version folder
	// e.g. https://repo.maven.apache.org/maven2/HTTPClient/HTTPClient/0.3-3/maven-metadata.xml
	if len(meta.Versioning.Versions) == 0 {
		return nil, nil
	}
	// also we need to skip metadata.xml files from groupID folder
	// e.g. https://repo.maven.apache.org/maven2/args4j/maven-metadata.xml
	if len(strings.Split(url, "/")) < 7 {
		return nil, nil
	}
	return &meta, nil
}

func (c *Crawler) fetchSHA1(ctx context.Context, url string) ([]byte, error) {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to new HTTP request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http get error (%s): %w", url, err)
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

func versionFromSha1URL(artifactId, sha1URL string) string {
	ss := strings.Split(sha1URL, "/")
	fileName := ss[len(ss)-1]
	return strings.TrimSuffix(strings.TrimPrefix(fileName, artifactId+"-"), ".jar.sha1")
}
