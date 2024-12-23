package crawler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
)

func TestCrawl(t *testing.T) {
	tests := []struct {
		name       string
		limit      int64
		lastUpdate time.Time
		fileNames  map[string]string
		goldenPath string
		filePath   string
		wantErr    string
	}{
		{
			name:  "happy path",
			limit: 1,
			fileNames: map[string]string{
				"/maven2/":                                              "testdata/happy/index.html",
				"/maven2/abbot/":                                        "testdata/happy/abbot.html",
				"/maven2/abbot/abbot/":                                  "testdata/happy/abbot_abbot.html",
				"/maven2/abbot/abbot/maven-metadata.xml":                "testdata/happy/maven-metadata.xml",
				"/maven2/abbot/abbot/0.12.3/":                           "testdata/happy/abbot_abbot_0.12.3.html",
				"/maven2/abbot/abbot/0.12.3/abbot-0.12.3.jar.sha1":      "testdata/happy/abbot-0.12.3.jar.sha1",
				"/maven2/abbot/abbot/0.13.0/":                           "testdata/happy/abbot_abbot_0.13.0.html",
				"/maven2/abbot/abbot/0.13.0/abbot-0.13.0.jar.sha1":      "testdata/happy/abbot-0.13.0.jar.sha1",
				"/maven2/abbot/abbot/0.13.0/abbot-0.13.0-copy.jar.sha1": "testdata/happy/abbot-0.13.0-copy.jar.sha1",
				"/maven2/abbot/abbot/1.4.0/":                            "testdata/happy/abbot_abbot_1.4.0.html",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0.jar.sha1":        "testdata/happy/abbot-1.4.0.jar.sha1",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0-lite.jar.sha1":   "testdata/happy/abbot-1.4.0-lite.jar.sha1",
			},
			goldenPath: "testdata/happy/abbot.json.golden",
			filePath:   "indexes/abbot/abbot.json",
		},
		{
			name:       "happy path with lastUpdate",
			limit:      1,
			lastUpdate: time.Date(2010, 01, 01, 01, 01, 01, 0, time.UTC),
			fileNames: map[string]string{
				"/maven2/":                                            "testdata/happy/index.html",
				"/maven2/abbot/":                                      "testdata/happy/abbot.html",
				"/maven2/abbot/abbot/":                                "testdata/happy/abbot_abbot.html",
				"/maven2/abbot/abbot/maven-metadata.xml":              "testdata/happy/maven-metadata.xml",
				"/maven2/abbot/abbot/1.4.0/":                          "testdata/happy/abbot_abbot_1.4.0.html",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0.jar.sha1":      "testdata/happy/abbot-1.4.0.jar.sha1",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0-lite.jar.sha1": "testdata/happy/abbot-1.4.0-lite.jar.sha1",
			},
			goldenPath: "testdata/happy/abbot-1.4.0.json.golden",
			filePath:   "indexes/abbot/abbot.json",
		},
		{
			name:  "sad path",
			limit: 2,
			fileNames: map[string]string{
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
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fileName, ok := tt.fileNames[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, fileName)
				w.WriteHeader(http.StatusOK)
				return
			}))
			defer ts.Close()

			tmpDir := t.TempDir()
			cl := crawler.NewCrawler(crawler.Option{
				RootUrl:    ts.URL + "/maven2/",
				Limit:      tt.limit,
				CacheDir:   tmpDir,
				LastUpdate: tt.lastUpdate,
			})

			err := cl.Crawl(context.Background())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			got, err := os.ReadFile(filepath.Join(tmpDir, tt.filePath))
			assert.NoError(t, err)

			want, err := os.ReadFile(tt.goldenPath)
			assert.NoError(t, err)

			assert.JSONEq(t, string(want), string(got))
		})
	}

}
