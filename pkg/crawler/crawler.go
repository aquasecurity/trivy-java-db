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
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/metadata"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

const mavenRepoURL = "https://repo.maven.apache.org/maven2/"

type Crawler struct {
	db   db.DB
	meta metadata.Client
	http *retryablehttp.Client

	rootUrl string
	wg      sync.WaitGroup
	urlCh   chan string
	indexCh chan *types.Index
	limit   *semaphore.Weighted
	clock   clock.Clock
}

type Option struct {
	Limit   int64
	RootUrl string
}

func NewCrawler(db db.DB, meta metadata.Client, opt Option) Crawler {
	client := retryablehttp.NewClient()
	client.Logger = nil

	if opt.RootUrl == "" {
		opt.RootUrl = mavenRepoURL
	}

	return Crawler{
		db:   db,
		meta: meta,
		http: client,

		rootUrl: opt.RootUrl,
		urlCh:   make(chan string, opt.Limit*10),
		indexCh: make(chan *types.Index, opt.Limit),
		limit:   semaphore.NewWeighted(opt.Limit),
		clock:   clock.RealClock{},
	}
}

func (c *Crawler) Crawl(ctx context.Context) error {
	errCh := make(chan error)
	defer close(errCh)

	// Add a root url
	c.urlCh <- c.rootUrl
	c.wg.Add(1)

	go func() {
		c.wg.Wait()
		close(c.urlCh)
	}()

	// For the HTTP loop
	go func() {
		defer close(c.indexCh)

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

	// For the DB loop
	dbDone := make(chan struct{})
	go func() {
		defer func() { dbDone <- struct{}{} }()

		var indexes []*types.Index
		for index := range c.indexCh {
			indexes = append(indexes, index)
			if len(indexes)%1000 == 0 {
				if err := c.db.InsertIndexes(indexes); err != nil {
					errCh <- err
					return
				}
				indexes = []*types.Index{} // clear array after saving to db
			}
		}
		// Insert the remaining indexes
		if err := c.db.InsertIndexes(indexes); err != nil {
			errCh <- err
			return
		}
	}()

loop:
	for {
		select {
		// Wait for DB update to complete
		case <-dbDone:
			break loop
		case err := <-errCh:
			close(c.urlCh)
			close(c.indexCh)
			return err

		}
	}

	// save metadata
	metaDB := metadata.Metadata{
		Version:    db.SchemaVersion,
		NextUpdate: c.clock.Now().UTC().Add(db.UpdateInterval),
		UpdatedAt:  c.clock.Now().UTC(),
	}

	err := c.meta.Update(metaDB)
	if err != nil {
		close(c.indexCh)
		close(c.urlCh)
		return err
	}

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
	for _, version := range meta.Versioning.Versions {
		sha1FileName := fmt.Sprintf("/%s-%s.jar.sha1", meta.ArtifactID, version)
		sha1, err := c.fetchSHA1(baseURL + version + sha1FileName)
		if err != nil {
			return err
		}
		if sha1 != "" {
			index := &types.Index{
				GroupID:     meta.GroupID,
				ArtifactID:  meta.ArtifactID,
				Version:     version,
				Sha1:        sha1,
				ArchiveType: types.JarType,
			}
			c.indexCh <- index
		}
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

func (c *Crawler) fetchSHA1(url string) (string, error) {
	resp, err := c.http.Get(url)
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
