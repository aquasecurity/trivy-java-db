package crawler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"

	_ "modernc.org/sqlite"
)

func TestCrawl(t *testing.T) {
	tests := []struct {
		name       string
		limit      int64
		mavenFiles map[string]string
		gcrFiles   map[string]string
		goldenPath string
		filePath   string
		wantErr    string
	}{
		{
			name:  "happy path",
			limit: 1,
			mavenFiles: map[string]string{
				"/maven2/":                                              "testdata/happy/index.html",
				"/maven2/abbot/":                                        "testdata/happy/abbot.html",
				"/maven2/abbot/abbot/":                                  "testdata/happy/abbot_abbot.html",
				"/maven2/abbot/abbot/maven-metadata.xml":                "testdata/happy/maven-metadata.xml",
				"/maven2/abbot/abbot/0.12.3/":                           "testdata/happy/abbot_abbot_0.12.3.html",
				"/maven2/abbot/abbot/0.13.0/":                           "testdata/happy/abbot_abbot_0.13.0.html",
				"/maven2/abbot/abbot/0.13.0/abbot-0.13.0.jar.sha1":      "testdata/happy/abbot-0.13.0.jar.sha1",
				"/maven2/abbot/abbot/0.13.0/abbot-0.13.0-copy.jar.sha1": "testdata/happy/abbot-0.13.0-copy.jar.sha1",
				"/maven2/abbot/abbot/1.4.0/":                            "testdata/happy/abbot_abbot_1.4.0.html",
				"/maven2/abbot/abbot/1.4.0/abbot-0.13.0.pom":            "testdata/happy/abbot-0.13.0.pom",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0.jar.sha1":        "testdata/happy/abbot-1.4.0.jar.sha1",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0-lite.jar.sha1":   "testdata/happy/abbot-1.4.0-lite.jar.sha1",
			},
			gcrFiles: map[string]string{
				"/maven2/abbot/abbot/0.12.3/abbot-0.12.3.jar.sha1": "testdata/happy/abbot-0.12.3.jar.sha1",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0.pom":        "testdata/happy/abbot-1.4.0.pom",
			},
			goldenPath: "testdata/happy/abbot.json.golden",
			filePath:   "indexes/abbot/abbot.json",
		},
		{
			name:  "sad path",
			limit: 2,
			mavenFiles: map[string]string{
				// index.html file for this test contains many links to avoid case
				// when we finish crawl and get error in one time.
				// We will get a `panic` because we will try to close `urlCh` in 2 places (after the wait group and after the error)
				// In real case it is impossible
				"/maven2/":                               "testdata/sad/index.html",
				"/maven2/abbot/":                         "testdata/sad/abbot.html",
				"/maven2/abbot/abbot/":                   "testdata/sad/abbot_abbot.html",
				"/maven2/abbot/abbot/maven-metadata.xml": "testdata/sad/maven-metadata.xml",
				"/maven2/HTTPClient/":                    "testdata/sad/httpclient.html",
				"/maven2/HTTPClient/HTTPClient/":         "testdata/sad/httpclient_httpclient.html",
				"/maven2/HTTPClient/maven-metadata.xml":  "testdata/sad/maven-metadata.xml",
			},
			wantErr: "decode error:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tsMaven := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serverResponse(t, tt.mavenFiles, w, r)
			}))
			defer tsMaven.Close()

			tsGCR := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serverResponse(t, tt.gcrFiles, w, r)
			}))
			defer tsGCR.Close()

			tmpDir := t.TempDir()

			cl, err := crawler.NewCrawler(crawler.Option{
				MavenUrl: tsMaven.URL + "/maven2/",
				GcrUrl:   tsGCR.URL + "/maven2/",
				Limit:    tt.limit,
				CacheDir: tmpDir,
			})
			require.NoError(t, err)

			err = cl.Crawl(context.Background())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			got, err := os.ReadFile(filepath.Join(tmpDir, tt.filePath))
			assert.NoError(t, err)

			want, err := os.ReadFile(tt.goldenPath)
			assert.NoError(t, err)

			assert.JSONEq(t, string(want), string(got))
		})
	}
}

func serverResponse(t *testing.T, files map[string]string, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	fileName, ok := files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, fileName)
	w.WriteHeader(http.StatusOK)
	return
}
