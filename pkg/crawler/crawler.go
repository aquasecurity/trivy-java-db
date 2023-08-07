package crawler

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"
)

const mavenRepoURL = "https://repo.maven.apache.org/maven2/"

type Crawler struct {
	dir  string
	http *retryablehttp.Client

	rootUrl string
	wg      sync.WaitGroup
	urlCh   chan string
	limit   *semaphore.Weighted
}

type Option struct {
	Limit    int64
	RootUrl  string
	CacheDir string
}

func NewCrawler(opt Option) Crawler {
	client := retryablehttp.NewClient()
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
				if err := c.Visit(url); err != nil {
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
			close(c.urlCh)
			return err

		}
	}
	log.Println("Crawl completed")
	return nil
}

func (c *Crawler) Visit(url string) error {
	resp, err := c.http.Get(url)
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
		meta, err := c.parseMetadata(url + "maven-metadata.xml")
		if err != nil {
			return xerrors.Errorf("metadata parse error: %w", err)
		}
		if meta != nil {
			if err = c.crawlSHA1(url, meta); err != nil {
				return err
			}
			// Return here since there is no need to crawl dirs anymore.
			return nil
		}
	}

	c.wg.Add(len(children))

	go func() {
		for _, child := range children {
			c.urlCh <- url + child
		}
	}()

	return nil
}

func (c *Crawler) crawlSHA1(baseURL string, meta *Metadata) error {
	var versions []Version
	for _, version := range meta.Versioning.Versions {
		sha1FileName := fmt.Sprintf("/%s-%s.jar.sha1", meta.ArtifactID, version)
		sha1, err := c.fetchSHA1(baseURL + version + sha1FileName)
		if err != nil {
			return err
		}
		if len(sha1) != 0 {
			// fetch licenses
			pomFileName := fmt.Sprintf("/%s-%s.pom", meta.ArtifactID, version)
			pomURL := baseURL + version + pomFileName
			pomLicense, err := c.fetchPOMLicense(pomURL)
			if err != nil {
				// TODO: Check if we can change this log to a warning or ignore it
				log.Println(err)
			}

			v := Version{
				Version: version,
				SHA1:    sha1,
				License: pomLicense,
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

func (c *Crawler) parseMetadata(url string) (*Metadata, error) {
	resp, err := c.http.Get(url)
	if err != nil {
		return nil, xerrors.Errorf("can't get url: %w", err)
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

func (c *Crawler) fetchSHA1(url string) ([]byte, error) {
	resp, err := c.http.Get(url)
	// some projects don't have xxx.jar and xxx.jar.sha1 files
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // TODO add special error for this
	}
	if err != nil {
		return nil, xerrors.Errorf("can't get sha1 from %s: %w", url, err)
	}
	defer resp.Body.Close()

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
		return nil, xerrors.Errorf("failed to decode sha1 %s: %w", url, err)
	}
	return sha1b, nil
}

func (c *Crawler) fetchPOMLicense(url string) (string, error) {
	resp, err := c.http.Get(url)
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if err != nil {
		return "", xerrors.Errorf("can't get pom xml from %s: %w", url, err)
	}
	defer resp.Body.Close()

	var pomProject gopom.Project

	decoder := xml.NewDecoder(resp.Body)
	decoder.CharsetReader = charset.NewReaderLabel
	err = decoder.Decode(&pomProject)

	if err != nil {
		return "", xerrors.Errorf("can't parse pom xml from %s: %w", url, err)
	}

	if len(pomProject.Licenses) == 0 {
		return "", nil
	}

	var licenses []string
	for _, l := range pomProject.Licenses {
		licenses = append(licenses, l.Name)
	}

	return strings.Join(licenses, ","), nil
}
