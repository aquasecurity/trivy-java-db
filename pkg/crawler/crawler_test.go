package crawler_test

import (
	"context"
	"encoding/hex"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
	"github.com/aquasecurity/trivy-java-db/pkg/metadata"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

func TestCraw(t *testing.T) {
	type testIndex struct {
		groupID     string
		artifactID  string
		version     string
		sha1        string
		archiveType types.ArchiveType
	}
	tests := []struct {
		name      string
		fileNames map[string]string
		want      []testIndex
		wantSha1  string
	}{
		{
			name: "happy path",
			fileNames: map[string]string{
				"/maven2/":                               "testdata/index.html",
				"/maven2/abbot/":                         "testdata/abbot.html",
				"/maven2/abbot/abbot/":                   "testdata/abbot_abbot.html",
				"/maven2/abbot/abbot/maven-metadata.xml": "testdata/maven-metadata.xml",
				"/maven2/abbot/abbot/0.12.3/abbot-0.12.3.jar.sha1": "testdata/abbot-0.12.3.jar.sha1",
				"/maven2/abbot/abbot/0.13.0/abbot-0.13.0.jar.sha1": "testdata/abbot-0.13.0.jar.sha1",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0.jar.sha1":   "testdata/abbot-1.4.0.jar.sha1",
			},
			want: []testIndex{
				{
					groupID:     "abbot",
					artifactID:  "abbot",
					version:     "0.12.3",
					sha1:        "51d28a27d919ce8690a40f4f335b9d591ceb16e9",
					archiveType: types.JarType,
				},
				{
					groupID:     "abbot",
					artifactID:  "abbot",
					version:     "0.13.0",
					sha1:        "596d91e67631b0deb05fb685d8d1b6735f3e4f60",
					archiveType: types.JarType,
				},
				{
					groupID:     "abbot",
					artifactID:  "abbot",
					version:     "1.4.0",
					sha1:        "a2363646a9dd05955633b450010b59a21af8a423",
					archiveType: types.JarType,
				},
			},
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

			//db, err := dbtest.InitDB(t, nil)
			tmpDir := t.TempDir()
			dbc, err := db.New(tmpDir)
			require.NoError(t, err)
			meta := metadata.New(dbc.Dir())
			cl := crawler.NewCrawler(dbc, meta, crawler.Option{
				RootUrl: ts.URL + "/maven2/",
				Limit:   1,
			})

			err = cl.Crawl(context.Background())
			assert.NoError(t, err)

			var want []types.Index
			// decode sha1
			for _, ti := range tt.want {
				sha1b, err := hex.DecodeString(ti.sha1)
				assert.NoError(t, err)
				index := types.Index{
					GroupID:     ti.groupID,
					ArtifactID:  ti.artifactID,
					Version:     ti.version,
					Sha1:        sha1b,
					ArchiveType: ti.archiveType,
				}
				want = append(want, index)
			}

			got, err := dbc.SelectIndexesByArtifactIDAndFileType("abbot", types.JarType)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}

}
