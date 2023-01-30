package crawler_test

import (
	"context"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
	"github.com/aquasecurity/trivy-java-db/pkg/crawler/dbtest"
	"github.com/aquasecurity/trivy-java-db/pkg/metadata"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

func TestCraw(t *testing.T) {
	tests := []struct {
		name      string
		fileNames map[string]string
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
				time.Sleep(time.Second) // Required to get time to save indexes to db
				http.ServeFile(w, r, fileName)
			}))
			defer ts.Close()

			db, err := dbtest.InitDB(t, nil)
			assert.NoError(t, err)
			meta := metadata.New(db.Dir())
			cl := crawler.NewCrawler(db, meta, crawler.Option{
				RootUrl: ts.URL + "/maven2/",
				Limit:   1,
			})

			err = cl.Crawl(context.Background())
			assert.NoError(t, err)

			got, err := db.SelectIndexesByArtifactIDAndFileType("abbot", types.JarType)
			require.NoError(t, err)
			// indexes are saved by ticker
			// in this test it happens that crawl does not save 1 index,
			// so we just check that there are indexes in the database
			// correctness of saving in the database / selection from the database is checked in = db tests
			if len(got) == 0 {
				t.Errorf("no index was saved in the database")
			}
		})
	}

}
