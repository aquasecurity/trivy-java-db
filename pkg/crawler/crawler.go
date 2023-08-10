package crawler

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/google/licenseclassifier/v2/tools/identify_license/backend"
	"github.com/samber/lo"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	cmap "github.com/orcaman/concurrent-map/v2"
	"golang.org/x/net/html/charset"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"
)

const mavenRepoURL = "https://repo.maven.apache.org/maven2/"

type Crawler struct {
	dir        string
	licensedir string
	http       *retryablehttp.Client

	rootUrl string
	wg      sync.WaitGroup
	urlCh   chan string
	limit   *semaphore.Weighted
	opt     Option

	// license classifier
	classifier *backend.ClassifierBackend

	// map of temporary license files created to license metadata
	filesLicenseMap cmap.ConcurrentMap[string, License]

	// uniqueLicenseKeys : key is hash of license url or name in POM, whichever available
	uniqueLicenseKeys cmap.ConcurrentMap[string, License]
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

	indexDir := filepath.Join(opt.CacheDir, types.IndexesDir)
	log.Printf("Index dir %s", indexDir)

	licensedir := filepath.Join(opt.CacheDir, types.LicenseDir)

	err := os.MkdirAll(licensedir, os.ModePerm)
	if err != nil {
		log.Panicf("panic while creating license cache directory %s .Error:%s", licensedir, err)
	}
	log.Printf("License dir %s", licensedir)

	classifier, err := backend.New()
	if err != nil {
		log.Panicf("panic while creating license classifier backend %s", err)
	}

	return Crawler{
		dir:        indexDir,
		licensedir: licensedir,
		http:       client,

		rootUrl:           opt.RootUrl,
		urlCh:             make(chan string, opt.Limit*10),
		limit:             semaphore.NewWeighted(opt.Limit),
		filesLicenseMap:   cmap.New[License](),
		classifier:        classifier,
		opt:               opt,
		uniqueLicenseKeys: cmap.New[License](),
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

	// fetch license information
	return c.classifyLicense()
}

// Visit : visits the maven urls.
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
			// analyze GAV information
			return c.crawlSHA1(url, meta)
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

			// fetch license information on the basis of pom url
			pomURL := getPomURL(baseURL, meta.ArtifactID, version)
			licenseKeys, err := c.fetchAndSavePOMLicenseKeys(pomURL)
			if err != nil {
				log.Println(err)
			}
			licenseKeys = lo.Uniq(licenseKeys)
			sort.Strings(licenseKeys)

			v := Version{
				Version: version,
				SHA1:    sha1,
				License: strings.Join(licenseKeys, "|"),
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

func (c *Crawler) fetchAndSavePOMLicenseKeys(url string) ([]string, error) {
	var keys []string
	resp, err := c.http.Get(url)
	if resp.StatusCode == http.StatusNotFound {
		return keys, nil
	}
	if err != nil {
		return keys, xerrors.Errorf("can't get pom xml from %s: %w", url, err)
	}
	defer resp.Body.Close()

	var pomProject PomProject

	decoder := xml.NewDecoder(resp.Body)
	decoder.CharsetReader = charset.NewReaderLabel
	err = decoder.Decode(&pomProject)

	if err != nil {
		return keys, xerrors.Errorf("can't parse pom xml from %s: %w", url, err)
	}

	if len(pomProject.Licenses) == 0 {
		return keys, nil
	}

	for _, l := range pomProject.Licenses {
		l.LicenseKey = getLicenseKey(l)

		// update uniqueLicenseKeys map
		c.uniqueLicenseKeys.Set(l.LicenseKey, l)

		keys = append(keys, l.LicenseKey)
	}

	return keys, nil

}

func (c *Crawler) classifyLicense() error {
	normalizedLicenseMap := make(map[string]string)

	// prepare classifier data i.e create temporary files with license text to be used for classification
	c.prepareClassifierData()

	if len(c.filesLicenseMap.Keys()) == 0 {
		return nil
	}

	// classify licenses

	// 1 minute is the timeout for license classification of a file
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// 1000 is the number of concurrent tasks spawned to process license files
	errs := c.classifier.ClassifyLicensesWithContext(ctx, 1000, c.filesLicenseMap.Keys(), true)
	if len(errs) > 0 {
		log.Println("errors in license classification ", errs)
	}

	// extract results
	results := c.classifier.GetResults()
	sort.Sort(results)

	// process results to update the filesLicenseMap
	if results.Len() > 0 {
		for _, r := range results {
			if licenseVal, ok := c.filesLicenseMap.Get(r.Filename); ok {
				// since results are sorted, we can skip processing of data with confidence <90%
				if r.Confidence < 0.9 {
					break
				}

				// skip processing since a higher confidence result is already processed
				if licenseVal.ClassificationConfidence > r.Confidence {
					continue
				}

				// update normalized license map
				normalizedLicenseMap[licenseVal.LicenseKey] = r.Name
			}
		}
	}

	defer func() {
		// update normalized license map for license keys which couldn't be classified or had no url in pom for classification
		uniqLicenseKeys := c.uniqueLicenseKeys.Items()
		for key, license := range uniqLicenseKeys {
			if _, ok := normalizedLicenseMap[key]; !ok {
				normalizedLicenseMap[key] = license.Name
			}
		}

		err := fileutil.WriteJSON(c.licensedir+types.NormalizedlicenseFileName, normalizedLicenseMap)
		if err != nil {
			log.Println(err)
		}
	}()

	return nil
}

func (c *Crawler) prepareClassifierData() {
	log.Println("Preparing license classifier data")

	batchSize := 10
	// batching for temporary licesene file creation
	// batch size hardcoded as 10
	totalBatches := len(c.uniqueLicenseKeys.Keys()) / batchSize
	if len(c.uniqueLicenseKeys.Keys()) != 0 {
		totalBatches = totalBatches + 1
	}

	log.Printf("Total batches to be processed %d", totalBatches)

	// process batches to created temporary license files
	for batch := 0; batch < totalBatches; batch++ {
		keyBatch := c.uniqueLicenseKeys.Keys()[batch*batchSize : min((batch+1)*batchSize, len(c.uniqueLicenseKeys.Keys()))]

		status := make(chan string, len(keyBatch))
		keysProcessed := 0
		for _, key := range keyBatch {
			go func(key string) {

				// get license metadata
				licenseMeta, _ := c.uniqueLicenseKeys.Get(key)

				// if url not available then no point using the license classifier
				// Names can be analyzed but in most cases license classifier does not result in any matches
				if !strings.HasPrefix(licenseMeta.URL, "http") {
					status <- "done"
					return
				}

				// temporary license file name
				file := fileutil.GetLicenseFileName(c.licensedir, key)

				// create file
				f, err := os.Create(file)
				if err != nil {
					log.Println(err)
					status <- "done"
					return
				}

				defer f.Close()

				// download license url contents
				resp, err := c.http.Get(licenseMeta.URL)
				if resp == nil {
					status <- "done"
					return
				}

				if resp.StatusCode == http.StatusNotFound {
					status <- "done"
					return
				}
				if err != nil {
					status <- "done"
					return
				}
				defer resp.Body.Close()

				_, err = io.Copy(f, resp.Body)
				if err != nil {
					status <- "done"
					return
				}

				// update filesLicenseMap
				c.filesLicenseMap.Set(file, licenseMeta)
				status <- "done"

			}(key)

		}

		// wait for batch to complete before proceeding
		for keysProcessed < len(keyBatch) {
			select {
			case _ = <-status:
				keysProcessed++
			case <-time.After(20 * time.Second):
				log.Println("prepareClassifierData timeout")
				keysProcessed++
			}
		}

		log.Printf("Total batches processed %d/%d", batch+1, totalBatches)
	}
}

func getLicenseKey(l License) string {
	if len(l.URL) > 0 && strings.HasPrefix(l.URL, "http") {
		return hash(l.URL)
	}
	return hash(l.Name)
}

func getPomURL(baseURL, artifactID, version string) string {
	pomFileName := fmt.Sprintf("/%s-%s.pom", artifactID, version)
	return baseURL + version + pomFileName
}

func hash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return fmt.Sprint(h.Sum32())
}

func min(a int, b int) int {
	if a > b {
		return b
	}
	return a
}
