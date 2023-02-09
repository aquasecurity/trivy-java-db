package dbtest

import (
	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-java-db/pkg/db"
)

func InitDB(t *testing.T, indexes []*db.Index) (db.DB, error) {
	tmpDir := t.TempDir()
	dbc, err := db.New(tmpDir)
	require.NoError(t, err)

	err = dbc.Init()
	require.NoError(t, err)

	if len(indexes) > 0 {
		err = dbc.InsertIndexes(convertIndexes(indexes))
		require.NoError(t, err)
	}
	require.NoError(t, err)
	return dbc, nil
}

func convertIndexes(indexes []*db.Index) []*crawler.Index {
	var crawlerIndexes []*crawler.Index
	for _, index := range indexes {
		ci := &crawler.Index{
			GroupID:     index.GroupID,
			ArtifactID:  index.ArtifactID,
			ArchiveType: index.ArchiveType,
			Versions: []crawler.Version{
				{
					Version: index.Version,
					SHA1:    index.SHA1,
				},
			},
		}
		crawlerIndexes = append(crawlerIndexes, ci)
	}
	return crawlerIndexes
}
