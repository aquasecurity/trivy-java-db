package crawler

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

const (
	mavenRepoURL = "https://repo1.maven.org/maven2/"
	// Define the bucket name and prefix.
	bucketName      = "maven-central"
	queryRootPrefix = "maven2/"
)

type Crawler struct {
	http *retryablehttp.Client

	rootUrl string
	dir     string

	wg              sync.WaitGroup
	limit           *semaphore.Weighted
	errOnce         sync.Once
	queryRootPrefix string

	// Number of Indexes
	count           int
	wrongSHA1Values []string
}

type Option struct {
	Limit    int64
	RootUrl  string
	CacheDir string
}

func NewCrawler(opt Option) (Crawler, error) {
	client := retryablehttp.NewClient()
	client.RetryMax = 10
	client.Logger = slog.Default()

	indexDir := filepath.Join(opt.CacheDir, types.IndexDir)
	slog.Info("Index dir", slog.String("path", indexDir))

	if opt.RootUrl == "" {
		opt.RootUrl = mavenRepoURL
	}

	return Crawler{
		http:            client,
		rootUrl:         opt.RootUrl,
		dir:             indexDir,
		limit:           semaphore.NewWeighted(opt.Limit),
		queryRootPrefix: queryRootPrefix,
	}, nil
}

func (c *Crawler) Crawl(ctx context.Context) error {
	slog.Info("Crawl maven repository and save indexes")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	dirs, err := c.getDirList(ctx)
	if err != nil {
		return xerrors.Errorf("unable to get dir list: %w", err)
	}

	doneCh := make(chan struct{})
	defer close(doneCh)
	errCh := make(chan error)
	defer close(errCh)

	c.wg.Add(1)
	go func() {
		c.wg.Wait()
		doneCh <- struct{}{}
	}()

	for _, dir := range dirs {
		if err = c.limit.Acquire(ctx, 1); err != nil {
			errCh <- xerrors.Errorf("semaphore acquire error: %w", err)
			break
		}

		go func() {
			c.wg.Add(1)
			defer c.wg.Done()
			defer c.limit.Release(1)

			if err = c.crawlDir(ctx, dir); err != nil {
				c.errOnce.Do(func() {
					errCh <- xerrors.Errorf("unable to crawl directory: %w", err)
				})
			}
		}()
	}
	c.wg.Done()

loop:
	for {
		select {
		case <-doneCh:
			slog.Info("Total saved indexes", slog.Int("count", c.count))
			break loop
		case err = <-errCh:
			cancel()
		}
	}

	if err != nil {
		return xerrors.Errorf("crawl error: %w", err)
	}

	return nil
}

func (c *Crawler) getDirList(ctx context.Context) ([]string, error) {
	slog.Info("Getting list if dirs")
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, c.rootUrl, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to create a HTTP request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http error (%s): %w", c.rootUrl, err)
	}
	defer resp.Body.Close()

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	var dirs []string
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := selection.Text()
		if link == "../" || !strings.HasSuffix(link, "/") {
			// only `../` and dirs have `/` suffix. We don't need to check other files.
			return
		}

		dirs = append(dirs, link)
	})

	return dirs, nil
}

func (c *Crawler) crawlDir(ctx context.Context, dir string) error {
	// Create a storage client without authentication (public bucket access).
	client, err := storage.NewClient(ctx, option.WithoutAuthentication())
	if err != nil {
		return xerrors.Errorf("unable to create storage client: %w", err)
	}
	defer client.Close()

	bucket := client.Bucket(bucketName)
	query := &storage.Query{
		Prefix:    path.Join(c.queryRootPrefix, dir),
		MatchGlob: "**jar.sha1",
	}

	err = query.SetAttrSelection([]string{"Name"})
	if err != nil {
		return xerrors.Errorf("unable to set attr selection: %w", err)
	}

	it := bucket.Objects(ctx, query)

	var index Index
	for {
		// Get the next object.
		obj, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		} else if err != nil {
			return xerrors.Errorf("failed to iterate objects: %w", err)
		}

		// Don't save sources, test, javadocs, scaladoc files
		if strings.HasSuffix(obj.Name, "sources.jar.sha1") || strings.HasSuffix(obj.Name, "test.jar.sha1") ||
			strings.HasSuffix(obj.Name, "tests.jar.sha1") || strings.HasSuffix(obj.Name, "javadoc.jar.sha1") ||
			strings.HasSuffix(obj.Name, "scaladoc.jar.sha1") {
			continue
		}

		// Retrieve the SHA1 file's content.
		sha1Content, err := retrieveObjectContent(ctx, bucket, obj.Name)
		if err != nil {
			return xerrors.Errorf("failed to retrieve content: %w", err)
		}

		sha1 := c.decodeSha1String(obj.Name, sha1Content)
		if len(sha1) == 0 {
			continue
		}

		groupID, artifactID, version := parseObjectName(obj.Name)
		if index.GroupID != groupID || index.ArtifactID != artifactID {
			// Save previous index
			if err := c.saveIndexToFile(index); err != nil {
				return xerrors.Errorf("failed to save index to file: %w", err)
			}

			// Init index with new GroupID and ArtifactID
			index = Index{
				GroupID:     groupID,
				ArtifactID:  artifactID,
				ArchiveType: types.JarType,
			}
		}

		// Save new version + sha1
		index.Versions = append(index.Versions, types.Version{
			Version: version,
			SHA1:    sha1,
		})

	}

	// Save last index
	if err = c.saveIndexToFile(index); err != nil {
		return xerrors.Errorf("failed to save index to file: %w", err)
	}

	if len(c.wrongSHA1Values) > 0 {
		for _, wrongSHA1 := range c.wrongSHA1Values {
			slog.Warn("Wrong SHA1 file", slog.String("error", wrongSHA1))
		}
	}

	return nil
}

// retrieveObjectContent retrieves and returns the content of an object.
func retrieveObjectContent(ctx context.Context, bucket *storage.BucketHandle, objectName string) (string, error) {
	obj := bucket.Object(objectName)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// parseBucketName parses object name and returns GroupID, ArtifactID and version of jar file
func parseObjectName(bucketName string) (string, string, string) {
	bucketName = strings.TrimPrefix(bucketName, "maven2/")
	ss := strings.Split(bucketName, "/")
	groupID := strings.Join(ss[:len(ss)-3], ".")
	artifactID := ss[len(ss)-3]
	// Take version from filename
	version := strings.TrimSuffix(strings.TrimPrefix(ss[len(ss)-1], artifactID+"-"), ".jar.sha1")
	return groupID, artifactID, version
}

func (c *Crawler) decodeSha1String(objName, sha1s string) []byte {
	// there are empty xxx.jar.sha1 files. Skip them.
	// e.g. https://repo.maven.apache.org/maven2/org/wso2/msf4j/msf4j-swagger/2.5.2/msf4j-swagger-2.5.2.jar.sha1
	// https://repo.maven.apache.org/maven2/org/wso2/carbon/analytics/org.wso2.carbon.permissions.rest.api/2.0.248/org.wso2.carbon.permissions.rest.api-2.0.248.jar.sha1
	if sha1s == "" {
		return nil
	}

	// there are xxx.jar.sha1 files with additional data. e.g.:
	// https://repo.maven.apache.org/maven2/aspectj/aspectjrt/1.5.2a/aspectjrt-1.5.2a.jar.sha1
	// https://repo.maven.apache.org/maven2/xerces/xercesImpl/2.9.0/xercesImpl-2.9.0.jar.sha1
	var err error
	for _, s := range strings.Split(strings.TrimSpace(sha1s), " ") {
		var sha1 []byte
		sha1, err = hex.DecodeString(s)
		if err == nil {
			return sha1
		}
	}
	c.wrongSHA1Values = append(c.wrongSHA1Values, fmt.Sprintf("%s (%s)", objName, err))
	return nil
}

func (c *Crawler) saveIndexToFile(index Index) error {
	if len(index.Versions) == 0 {
		return nil
	}

	// Remove duplicates and save artifacts without extra suffixes.
	// e.g. `cudf-0.14-cuda10-1.jar.sha1` and `cudf-0.14.jar.sha1` => `cudf-0.14.jar.sha1`
	//  https://repo.maven.apache.org/maven2/ai/rapids/cudf/0.14/
	index.Versions = lo.Reverse(index.Versions)
	index.Versions = lo.UniqBy(index.Versions, func(v types.Version) string {
		return string(v.SHA1)
	})

	fileName := fmt.Sprintf("%s.json", index.ArtifactID)
	filePath := filepath.Join(c.dir, index.GroupID, fileName)
	if err := fileutil.WriteJSON(filePath, index); err != nil {
		return xerrors.Errorf("json write error: %w", err)
	}

	c.count++
	if c.count%1000 == 0 {
		slog.Info("Saved indexes", slog.Int("count", c.count))
	}
	return nil
}
