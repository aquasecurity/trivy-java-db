package crawler_test

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy-java-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"

	_ "modernc.org/sqlite"
)

func TestCrawl(t *testing.T) {
	tests := []struct {
		name       string
		limit      int64
		fileNames  map[string]string
		withDb     bool
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
			name:   "happy path with DB",
			withDb: true,
			limit:  1,
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
			goldenPath: "testdata/happy/abbot-with-db.json.golden",
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
			if tt.withDb {
				dbc, err := dbtest.InitDB(t, []types.Index{
					indexAbbot123,
					indexAbbot130,
				})
				require.NoError(t, err)

				tmpDir = filepath.Join(strings.TrimSuffix(dbc.Dir(), "db"))
			}

			cl, err := crawler.NewCrawler(crawler.Option{
				RootUrl:  ts.URL + "/maven2/",
				Limit:    tt.limit,
				CacheDir: tmpDir,
			})
			require.NoError(t, err)

			err = cl.Crawl(context.Background())
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

var (
	abbot123Sha1b, _ = hex.DecodeString("51d28a27d919ce8690a40f4f335b9d591ceb16e9")
	indexAbbot123    = types.Index{
		GroupID:     "abbot",
		ArtifactID:  "abbot",
		Version:     "0.12.3",
		SHA1:        abbot123Sha1b,
		ArchiveType: types.JarType,
	}

	abbot130Sha1b, _ = hex.DecodeString("596d91e67631b0deb05fb685d8d1b6735f3e4f60")
	indexAbbot130    = types.Index{
		GroupID:     "abbot",
		ArtifactID:  "abbot",
		Version:     "0.13.0",
		SHA1:        abbot130Sha1b,
		ArchiveType: types.JarType,
	}
)
