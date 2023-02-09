package dbtest

import (
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-java-db/pkg/db"
)

func InitDB(t *testing.T, indexes []types.Index) (db.DB, error) {
	tmpDir := t.TempDir()
	dbc, err := db.New(tmpDir)
	require.NoError(t, err)

	err = dbc.Init()
	require.NoError(t, err)

	err = dbc.InsertIndexes(indexes)
	require.NoError(t, err)
	return dbc, nil
}
