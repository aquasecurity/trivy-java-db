package crawler_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy-java-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"

	_ "modernc.org/sqlite"
)

func TestCrawl(t *testing.T) {
	tests := []struct {
		name              string
		limit             int64
		maxResults        int
		fileNames         map[string]string
		withDb            bool
		mavenCentralError bool
		gcsApiError       bool
		goldenPath        string
		filePath          string
		wantErr           string
	}{
		{
			name:       "happy path",
			limit:      2,
			maxResults: 3,
			fileNames: map[string]string{
				"maven2/abbot/abbot/0.12.3/abbot-0.12.3.jar.sha1":      "testdata/happy/abbot-0.12.3.jar.sha1",
				"maven2/abbot/abbot/0.13.0/abbot-0.13.0.jar.sha1":      "testdata/happy/abbot-0.13.0.jar.sha1",
				"maven2/abbot/abbot/0.13.0/abbot-0.13.0-copy.jar.sha1": "testdata/happy/abbot-0.13.0-copy.jar.sha1",
				"maven2/abbot/abbot/1.4.0/abbot-1.4.0.jar.sha1":        "testdata/happy/abbot-1.4.0.jar.sha1",
				"maven2/abbot/abbot/1.4.0/abbot-1.4.0-lite.jar.sha1":   "testdata/happy/abbot-1.4.0-lite.jar.sha1",
			},
			goldenPath: "testdata/happy/abbot.json.golden",
			filePath:   "indexes/abbot/abbot.json",
		},
		{
			name:       "happy path with DB",
			withDb:     true,
			limit:      2,
			maxResults: 3,
			fileNames: map[string]string{
				"maven2/abbot/abbot/0.12.3/abbot-0.12.3.jar.sha1":      "testdata/happy/abbot-0.12.3.jar.sha1",
				"maven2/abbot/abbot/0.13.0/abbot-0.13.0.jar.sha1":      "testdata/happy/abbot-0.13.0.jar.sha1",
				"maven2/abbot/abbot/0.13.0/abbot-0.13.0-copy.jar.sha1": "testdata/happy/abbot-0.13.0-copy.jar.sha1",
				"maven2/abbot/abbot/1.4.0/abbot-1.4.0.jar.sha1":        "testdata/happy/abbot-1.4.0.jar.sha1",
				"maven2/abbot/abbot/1.4.0/abbot-1.4.0-lite.jar.sha1":   "testdata/happy/abbot-1.4.0-lite.jar.sha1",
			},
			goldenPath: "testdata/happy/abbot-with-db.json.golden",
			filePath:   "indexes/abbot/abbot.json",
		},
		{
			name:              "sad path. Maven central error",
			limit:             2,
			mavenCentralError: true,
			wantErr:           "unable to get root dirs",
		},
		{
			name:        "sad path. GCS API error",
			limit:       2,
			gcsApiError: true,
			wantErr:     "HTTP request failed after retries",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.mavenCentralError {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				http.ServeFile(w, r, "testdata/happy/index.html")
				w.WriteHeader(http.StatusOK)
				return
			}))
			defer mts.Close()

			sha1List := lo.Keys(tt.fileNames)
			slices.Sort(sha1List)

			gts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.String(), ".jar.sha1") {
					require.NoError(t, writeSha1(t, w, r, tt.fileNames))
					return
				}

				if tt.gcsApiError {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				require.NoError(t, writeGCSResponse(t, w, r, sha1List, tt.maxResults))

			}))
			defer gts.Close()

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
				MavenUrl:     mts.URL + "/maven2/",
				GcsUrl:       gts.URL + "/",
				Limit:        tt.limit,
				CacheDir:     tmpDir,
				WithoutRetry: true,
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

func writeSha1(t *testing.T, w http.ResponseWriter, r *http.Request, fileNames map[string]string) error {
	t.Helper()
	url := strings.TrimPrefix(r.URL.String(), "/maven-central/")
	testFilePath, ok := fileNames[url]
	if !ok {
		return xerrors.Errorf("unable to find file: %s", r.URL.Path)
	}
	http.ServeFile(w, r, testFilePath)
	w.WriteHeader(http.StatusOK)
	return nil
}

func writeGCSResponse(t *testing.T, w http.ResponseWriter, r *http.Request, sha1Urls []string, maxResults int) error {
	t.Helper()
	var token int
	q := r.URL.Query()
	if qResult := q.Get("pageToken"); qResult != "" {
		var err error
		token, err = strconv.Atoi(qResult)
		if err != nil {
			return err
		}
	}

	resp := crawler.GcsApiResponse{}

	for i := token * maxResults; i < token*maxResults+maxResults; i++ {
		resp.Items = append(resp.Items, crawler.Item{
			Name: sha1Urls[i],
		})

		if i == len(sha1Urls)-1 {
			token = -1
		}
	}
	if token != -1 {
		resp.NextPageToken = strconv.Itoa(token + 1)
	}

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonResp)
	if err != nil {
		return err
	}

	return nil
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
