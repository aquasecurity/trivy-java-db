package collector

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/PuerkitoBio/goquery"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
)

const mavenRepoURL = "https://repo.maven.apache.org/maven2/"

func CollectProjects() error {
	parseMainURL()
	return nil
}

func parseMainURL() error {
	ctx := context.TODO()
	limit := semaphore.NewWeighted(100)

	resp, err := http.Get(mavenRepoURL)
	if err != nil {
		return xerrors.Errorf("can't maven repository(%s): %w", mavenRepoURL, err)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := selection.Text()
		// only `../` and dirs have `/` suffix. We don't need to check other files.
		if link != "../" && strings.HasSuffix(link, "/") {
			if err := limit.Acquire(ctx, 1); err != nil {
				log.Printf("Failed to acquire semaphore: %v", err)
				return
			}
			go func() {
				defer limit.Release(1)
				err := parseURL(mavenRepoURL + link)
				if err != nil {
					log.Printf("can't parse URL: %s", err) // TODO add logger???
				}
			}()
		}

	})
	return nil
}

func parseURL(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return xerrors.Errorf("can't get url: %w", err)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := selection.Text()
		if link == "maven-metadata.xml" {
			meta, _ := getMetadata(url + link)
			for _, version := range meta.Versioning.Versions.Version {
				sha1FileName := fmt.Sprintf("/%s-%s.jar.sha1", meta.ArtifactID, version)
				sha1, err := getSha1(url + version + sha1FileName)
				if err != nil {
					fmt.Printf("error: %s", err) // TODO add logger???
					return
				}
				if sha1 != "" {
					err := db.InsertIndex(meta.GroupID, meta.ArtifactID, version, sha1)
					if err != nil {
						fmt.Printf("error: %s", err) // TODO add logger???
						return
					}
				}
			}
		}
		if link != "../" && strings.HasSuffix(link, "/") {
			err := parseURL(url + link)
			if err != nil {
				log.Printf("can't parse URL: %s", err) // TODO add logger???
			}
		}

	})
	return nil
}

func getMetadata(url string) (*Metadata, error) {
	resp, err := http.Get(url)
	if err != nil {
		return &Metadata{}, xerrors.Errorf("can't get url: %w", err)
	}
	body := resp.Body
	defer body.Close()
	decoder := xml.NewDecoder(resp.Body)
	metadata := &Metadata{}
	err = decoder.Decode(metadata)
	if err != nil {
		return &Metadata{}, xerrors.Errorf("can't parse %s file: %w", url, err)
	}
	// we don't need metadata.xml files from version folder
	// e.g. https://repo.maven.apache.org/maven2/HTTPClient/HTTPClient/0.3-3/maven-metadata.xml
	if len(metadata.Versioning.Versions.Version) == 0 {
		return &Metadata{}, nil
	}
	// also we need to skip metadata.xml files from groupID folder
	// e.g. https://repo.maven.apache.org/maven2/args4j/maven-metadata.xml
	if len(strings.Split(url, "/")) < 7 {
		return &Metadata{}, nil
	}
	return metadata, nil
}

func getSha1(url string) (string, error) {
	resp, err := http.Get(url)
	// some projects don't have xxx.jar and xxx.jar.sha1 files
	if resp.StatusCode == http.StatusNotFound {
		return "", nil // TODO add special error for this
	}
	if err != nil {
		return "", xerrors.Errorf("can't get sha1 from %s: %w", url, err)
	}
	body := resp.Body
	defer body.Close()
	sha1, err := io.ReadAll(body)
	if err != nil {
		return "", xerrors.Errorf("can't read sha1 %s: %w", url, err)
	}
	// there are xxx.jar.sha1 files with additional data. Sha1 is always 1st word.
	// e.g.https://repo.maven.apache.org/maven2/aspectj/aspectjrt/1.5.2a/aspectjrt-1.5.2a.jar.sha1
	return strings.Split(strings.TrimSpace(string(sha1)), " ")[0], err
}
