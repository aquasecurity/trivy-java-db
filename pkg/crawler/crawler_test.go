package crawler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
	"github.com/aquasecurity/trivy-java-db/pkg/crawler/gcs"

	_ "modernc.org/sqlite"
)

func TestCrawl(t *testing.T) {
	tests := []struct {
		name        string
		limit       int
		maxResults  int
		withIndex   bool
		fileNames   map[string]string
		gcsApiError bool
		goldenPath  string
		filePath    string
		wantErr     string
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
			goldenPath: "testdata/happy/abbot.tsv.golden",
			filePath:   "maven-index/03.tsv",
		},
		{
			name:       "happy path with the existing index",
			withIndex:  true,
			limit:      2,
			maxResults: 3,
			fileNames: map[string]string{
				"maven2/abbot/abbot/0.12.3/abbot-0.12.3.jar.sha1":      "testdata/happy/abbot-0.12.3.jar.sha1",
				"maven2/abbot/abbot/0.13.0/abbot-0.13.0.jar.sha1":      "testdata/happy/abbot-0.13.0.jar.sha1",
				"maven2/abbot/abbot/0.13.0/abbot-0.13.0-copy.jar.sha1": "testdata/happy/abbot-0.13.0-copy.jar.sha1",
				"maven2/abbot/abbot/1.4.0/abbot-1.4.0.jar.sha1":        "testdata/happy/abbot-1.4.0.jar.sha1",
				"maven2/abbot/abbot/1.4.0/abbot-1.4.0-lite.jar.sha1":   "testdata/happy/abbot-1.4.0-lite.jar.sha1",
			},
			goldenPath: "testdata/happy/abbot-with-index.tsv.golden",
			filePath:   "maven-index/03.tsv",
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
			sha1List := lo.Keys(tt.fileNames)
			slices.Sort(sha1List)

			gts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// GCS prefix API (for TopLevelPrefixes etc)
				if delimiter := r.URL.Query().Get("delimiter"); delimiter != "" {
					resp := gcs.ListResponse{
						Prefixes: []string{
							"maven2/abbot/",
						},
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(resp)
					return
				}

				if strings.HasSuffix(r.URL.String(), ".jar.sha1") {
					err := writeSHA1(t, w, r, tt.fileNames)
					require.NoError(t, err)
					return
				}

				if tt.gcsApiError {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				err := writeGCSResponse(t, w, r, sha1List, tt.maxResults)
				require.NoError(t, err)

			}))
			defer gts.Close()

			tmpDir := t.TempDir()

			// If withIndex is true, create an existing index file with intentionally different digest values.
			// This is to verify that the record is skipped even if the digest does not match the actual value.
			if tt.withIndex {
				indexPath := filepath.Join(tmpDir, "maven-index/03.tsv")
				if err := os.MkdirAll(filepath.Dir(indexPath), 0755); err != nil {
					t.Fatalf("failed to create index dir: %v", err)
				}
				// The digest is intentionally set to all zeros to check that the record is skipped and not updated.
				indexContent := "abbot\tabbot\t1.4.0\t\t0000000000000000000000000000000000000000\nabbot\tabbot\t1.4.0\tlite\t0000000000000000000000000000000000000000\n"
				if err := os.WriteFile(indexPath, []byte(indexContent), 0644); err != nil {
					t.Fatalf("failed to write index file: %v", err)
				}
			}

			cl, err := crawler.NewCrawler(crawler.Option{
				BaseURL:      gts.URL + "/",
				Limit:        tt.limit,
				CacheDir:     tmpDir,
				IndexDir:     filepath.Join(tmpDir, "maven-index"),
				Shard:        4,
				WithoutRetry: true,
			})
			require.NoError(t, err)

			err = cl.Crawl(context.Background())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			got, err := os.ReadFile(filepath.Join(tmpDir, tt.filePath))
			require.NoError(t, err)

			want, err := os.ReadFile(tt.goldenPath)
			assert.NoError(t, err)

			gotLines := strings.Split(strings.TrimSpace(string(got)), "\n")
			wantLines := strings.Split(strings.TrimSpace(string(want)), "\n")
			slices.Sort(gotLines)
			slices.Sort(wantLines)
			assert.Equal(t, wantLines, gotLines)
		})
	}
}

func writeSHA1(t *testing.T, w http.ResponseWriter, r *http.Request, fileNames map[string]string) error {
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

func writeGCSResponse(t *testing.T, w http.ResponseWriter, r *http.Request, sha1URLs []string, maxResults int) error {
	t.Helper()
	resp := gcs.ListResponse{}
	q := r.URL.Query()

	pageToken := q.Get("pageToken")
	if pageToken == "" {
		resp.NextPageToken = "0"
	} else {
		token, err := strconv.Atoi(pageToken)
		if err != nil {
			return err
		}

		chunk := lo.Chunk(sha1URLs, maxResults)
		resp.Items = lo.Map(chunk[token], func(url string, _ int) gcs.Item {
			return gcs.Item{
				Name: url,
			}
		})

		if token < len(chunk)-1 {
			resp.NextPageToken = strconv.Itoa(token + 1)
		}
	}

	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(resp)
}
