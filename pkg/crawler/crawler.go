package crawler

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
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

	// uniqueLicenseKeys : key is hash of license url or name in POM, whichever available
	uniqueLicenseKeys cmap.ConcurrentMap[string, License]
}

type Option struct {
	Limit    int64
	RootUrl  string
	CacheDir string
}

type licenseFilesMeta struct {
	FileName string
	License
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
	return c.classifyLicense(ctx)
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

func (c *Crawler) classifyLicense(ctx context.Context) error {
	normalizedLicenseMap := make(map[string]string)

	// prepare classifier data i.e create temporary files with license text to be used for classification
	licenseFiles, err := c.prepareClassifierData(ctx)
	if err != nil {
		return err
	}

	files := make([]string, 0)
	filesLicenseMap := make(map[string]License)

	// change license file list to map
	for _, data := range licenseFiles {
		if _, ok := filesLicenseMap[data.FileName]; !ok {
			filesLicenseMap[data.FileName] = data.License
			files = append(files, data.FileName)
		}
	}

	if len(filesLicenseMap) == 0 {
		return nil
	}

	// classify licenses

	// 1 minute is the timeout for license classification of a file
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// c.opt.Limit is the number of concurrent tasks spawned to process license files
	errs := c.classifier.ClassifyLicensesWithContext(ctx, int(c.opt.Limit), files, true)
	if len(errs) > 0 {
		log.Println("errors in license classification ", errs)
	}

	// extract results
	results := c.classifier.GetResults()
	sort.Sort(results)

	// process results to update the normalizedLicenseMap
	if results.Len() > 0 {
		for _, r := range results {
			if licenseVal, ok := filesLicenseMap[r.Filename]; ok {
				// since results are sorted, we can skip processing of data with confidence <90%
				if r.Confidence < 0.9 {
					break
				}

				// skip processing since a higher confidence result is already processed
				if licenseVal.ClassificationConfidence > r.Confidence {
					continue
				}

				licenseVal.ClassificationConfidence = r.Confidence
				filesLicenseMap[r.Filename] = licenseVal

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

func (c *Crawler) prepareClassifierData(ctx context.Context) ([]licenseFilesMeta, error) {
	log.Println("Preparing license classifier data")

	var licenseFiles []licenseFilesMeta

	// switch from concurrent to normal map
	uniqLicenseKeyMap := c.uniqueLicenseKeys.Items()
	uniqueLicenseKeyList := c.uniqueLicenseKeys.Keys()

	licenseKeyChannel := make(chan string, len(uniqueLicenseKeyList))

	log.Printf("Total license keys to be processed %d", len(uniqueLicenseKeyList))

	// dump license keys to the channel so that they can be processed
	for _, key := range uniqueLicenseKeyList {
		licenseKeyChannel <- key
	}

	limit := semaphore.NewWeighted(c.opt.Limit)

	// error channel
	errCh := make(chan error)
	defer close(errCh)

	// status channel to track processing of license keys
	type status struct {
		Meta licenseFilesMeta
		Done bool
	}
	prepStatus := make(chan status, len(uniqueLicenseKeyList))
	defer close(prepStatus)

	// process license keys channel
	go func() {
		for licenseKey := range licenseKeyChannel {

			if err := limit.Acquire(ctx, 1); err != nil {
				errCh <- xerrors.Errorf("semaphore acquire error: %w", err)
			}

			// process license key to generate license file
			go func(licenseKey string) {
				defer limit.Release(1)

				licenseFileName := getLicenseFileName(c.licensedir, licenseKey)
				licenseMeta := uniqLicenseKeyMap[licenseKey]
				ok, err := c.generateLicenseFile(licenseFileName, licenseMeta)
				if err != nil {
					errCh <- xerrors.Errorf("generateLicenseFile error: %w", err)
				}

				// update status post processing of license key
				prepStatus <- status{
					Done: ok,
					Meta: licenseFilesMeta{
						License:  licenseMeta,
						FileName: licenseFileName,
					},
				}
			}(licenseKey)
		}
	}()

	count := 0
loop:
	for {
		select {
		case status := <-prepStatus:
			count++
			if status.Done {
				licenseFiles = append(licenseFiles, status.Meta)
			}

			if count%1000 == 0 {
				log.Printf("Processed %d license keys", count)
			}

			if count == len(uniqueLicenseKeyList) {
				close(licenseKeyChannel)
				break loop
			}
		case err := <-errCh:
			close(licenseKeyChannel)
			return licenseFiles, err

		}
	}

	log.Println("Preparation of license classifier data completed")

	return licenseFiles, nil

}

func (c *Crawler) generateLicenseFile(licenseFileName string, licenseMeta License) (bool, error) {
	client := http.Client{
		Timeout: 10 * time.Second,
	}

	// if url not available then no point using the license classifier
	// Names can be analyzed but in most cases license classifier does not result in any matches
	if !strings.HasPrefix(licenseMeta.URL, "http") {
		return false, nil
	}

	// create file
	f, err := os.Create(licenseFileName)
	if err != nil {
		return false, err
	}

	defer f.Close()

	// download license url contents
	resp, err := client.Get(licenseMeta.URL)
	if resp == nil {
		return false, nil
	}

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return false, err
	}

	return true, nil
}
