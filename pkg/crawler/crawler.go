package crawler

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"
)

const mavenRepoURL = "https://repo.maven.apache.org/maven2/"

type Crawler struct {
	wg     sync.WaitGroup
	urlCh  chan string
	limit  *semaphore.Weighted
	client *retryablehttp.Client
}

type Option struct {
	Limit int64
}

func NewCrawler(opt Option) Crawler {
	client := retryablehttp.NewClient()
	client.Logger = nil
	return Crawler{
		urlCh:  make(chan string, opt.Limit*10),
		limit:  semaphore.NewWeighted(opt.Limit),
		client: client,
	}
}

func (c *Crawler) Crawl(ctx context.Context) error {
	errCh := make(chan error)
	defer close(errCh)

	// Add a root url
	c.urlCh <- mavenRepoURL
	c.wg.Add(1)

	go func() {
		c.wg.Wait()
		close(c.urlCh)
	}()

	var count int
loop:
	for {
		select {
		case url, ok := <-c.urlCh:
			count++
			if count%1000 == 0 {
				log.Printf("Count: %d", count)
			}
			if !ok {
				// channel is closed
				break loop
			}
			if err := c.limit.Acquire(ctx, 1); err != nil {
				return xerrors.Errorf("semaphore acquire error: %w", err)
			}
			go func() {
				defer c.limit.Release(1)
				defer c.wg.Done()
				if err := c.Visit(url); err != nil {
					errCh <- xerrors.Errorf("visit error: %w", err)
				}
			}()
		case err := <-errCh:
			close(c.urlCh)
			return err
		}
	}

	return nil
}

func (c *Crawler) Visit(url string) error {
	resp, err := c.client.Get(url)
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
	for _, version := range meta.Versioning.Versions {
		sha1FileName := fmt.Sprintf("/%s-%s.jar.sha1", meta.ArtifactID, version)
		sha1, err := c.fetchSHA1(baseURL + version + sha1FileName)
		if err != nil {
			return err
		}
		if sha1 != "" {
			if err = db.InsertIndex(meta.GroupID, meta.ArtifactID, version, sha1); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Crawler) parseMetadata(url string) (*Metadata, error) {
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, xerrors.Errorf("can't get url: %w", err)
	}
	defer resp.Body.Close()

	var metadata Metadata
	if err = xml.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, xerrors.Errorf("%s decode error: %w", url, err)
	}
	// we don't need metadata.xml files from version folder
	// e.g. https://repo.maven.apache.org/maven2/HTTPClient/HTTPClient/0.3-3/maven-metadata.xml
	if len(metadata.Versioning.Versions) == 0 {
		return nil, nil
	}
	// also we need to skip metadata.xml files from groupID folder
	// e.g. https://repo.maven.apache.org/maven2/args4j/maven-metadata.xml
	if len(strings.Split(url, "/")) < 7 {
		return nil, nil
	}
	return &metadata, nil
}

func (c *Crawler) fetchSHA1(url string) (string, error) {
	resp, err := c.client.Get(url)
	// some projects don't have xxx.jar and xxx.jar.sha1 files
	if resp.StatusCode == http.StatusNotFound {
		return "", nil // TODO add special error for this
	}
	if err != nil {
		return "", xerrors.Errorf("can't get sha1 from %s: %w", url, err)
	}
	defer resp.Body.Close()

	sha1, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", xerrors.Errorf("can't read sha1 %s: %w", url, err)
	}
	// there are xxx.jar.sha1 files with additional data. Sha1 is always 1st word.
	// e.g.https://repo.maven.apache.org/maven2/aspectj/aspectjrt/1.5.2a/aspectjrt-1.5.2a.jar.sha1
	return strings.Split(strings.TrimSpace(string(sha1)), " ")[0], nil
}
