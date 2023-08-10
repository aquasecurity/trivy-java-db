package crawler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
)

func TestCrawl(t *testing.T) {
	tests := []struct {
		name                        string
		fileNames                   map[string]string
		goldenPath                  string
		goldenNormalizedlicensePath string
		filePath                    string
		normalizedLicensePath       string
	}{
		{
			name: "happy path",
			fileNames: map[string]string{
				"/maven2/":                               "testdata/index.html",
				"/maven2/abbot/":                         "testdata/abbot.html",
				"/maven2/abbot/abbot/":                   "testdata/abbot_abbot.html",
				"/maven2/abbot/abbot/maven-metadata.xml": "testdata/maven-metadata.xml",
				"/maven2/abbot/abbot/0.12.3/abbot-0.12.3.jar.sha1": "testdata/abbot-0.12.3.jar.sha1",
				"/maven2/abbot/abbot/0.12.3/abbot-0.12.3.pom":      "testdata/abbot-0.12.3.pom",
				"/maven2/abbot/abbot/0.13.0/abbot-0.13.0.jar.sha1": "testdata/abbot-0.13.0.jar.sha1",
				"/maven2/abbot/abbot/0.13.0/abbot-0.13.0.pom":      "testdata/abbot-0.13.0.pom",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0.jar.sha1":   "testdata/abbot-1.4.0.jar.sha1",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0.pom":        "testdata/abbot-1.4.0.pom",
			},
			goldenPath:                  "testdata/golden/abbot.json",
			goldenNormalizedlicensePath: "testdata/golden/normalized_license.json",

			filePath:              "indexes/abbot/abbot.json",
			normalizedLicensePath: "licenses/normalized_license.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fileName, ok := tt.fileNames[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, fileName)
			}))
			defer ts.Close()

			tmpDir := t.TempDir()
			cl := crawler.NewCrawler(crawler.Option{
				RootUrl:  ts.URL + "/maven2/",
				Limit:    1,
				CacheDir: tmpDir,
			})

			err := cl.Crawl(context.Background())
			assert.NoError(t, err)

			got, err := os.ReadFile(filepath.Join(tmpDir, tt.filePath))
			assert.NoError(t, err)

			want, err := os.ReadFile(tt.goldenPath)
			assert.NoError(t, err)

			assert.JSONEq(t, string(want), string(got))

			// normalized license json file check
			got, err = os.ReadFile(filepath.Join(tmpDir, tt.normalizedLicensePath))
			assert.NoError(t, err)

			want, err = os.ReadFile(tt.goldenNormalizedlicensePath)
			assert.NoError(t, err)

			assert.JSONEq(t, string(want), string(got))

		})
	}

}
