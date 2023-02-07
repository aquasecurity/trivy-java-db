package dbtest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

func InitDB(t *testing.T, indexes []*types.Index) (db.DB, error) {
	tmpDir := t.TempDir()
	dbc, err := db.New(tmpDir)
	require.NoError(t, err)

	err = dbc.Init()
	require.NoError(t, err)

	if len(indexes) > 0 {
		err = dbc.InsertIndexes(indexes)
		require.NoError(t, err)
	}
	require.NoError(t, err)
	return dbc, nil
}
