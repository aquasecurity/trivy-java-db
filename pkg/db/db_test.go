package db_test

import (
	"github.com/aquasecurity/trivy-java-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	indexJstl = types.Index{
		GroupID:     "jstl",
		ArtifactID:  "jstl",
		Version:     "1.0",
		Sha1:        "9c581de633e94be1e7a955bd4e8292f16e554387",
		ArchiveType: types.JarType,
	}
	indexJavaxServlet = types.Index{
		GroupID:     "javax.servlet",
		ArtifactID:  "jstl",
		Version:     "1.1.0",
		Sha1:        "bca201e52333629c59e459e874e5ecd8f9899e15",
		ArchiveType: types.JarType,
	}
)

func TestSelectIndexBySha1(t *testing.T) {
	tests := []struct {
		name      string
		sha1      string
		want      types.Index
		assertErr assert.ErrorAssertionFunc
	}{
		{
			name:      "happy path",
			sha1:      "9c581de633e94be1e7a955bd4e8292f16e554387",
			want:      indexJstl,
			assertErr: assert.NoError,
		},
		{
			name:      "wrong sha1",
			sha1:      "wrong",
			want:      types.Index{},
			assertErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbc, err := dbtest.InitDB(t, []*types.Index{
				&indexJstl,
				&indexJavaxServlet,
			})
			require.NoError(t, err)

			got, err := dbc.SelectIndexBySha1(tt.sha1)
			tt.assertErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSelectIndexByArtifactIDAndGroupID(t *testing.T) {
	tests := []struct {
		name       string
		groupID    string
		artifactID string
		want       types.Index
		assertErr  assert.ErrorAssertionFunc
	}{
		{
			name:       "happy path",
			groupID:    "javax.servlet",
			artifactID: "jstl",
			want:       indexJavaxServlet,
			assertErr:  assert.NoError,
		},
		{
			name:       "wrong ArtifactID",
			groupID:    "javax.servlet",
			artifactID: "wrong",
			want:       types.Index{},
			assertErr:  assert.NoError,
		},
		{
			name:       "wrong GroupID",
			groupID:    "wrong",
			artifactID: "jstl",
			want:       types.Index{},
			assertErr:  assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbc, err := dbtest.InitDB(t, []*types.Index{
				&indexJstl,
				&indexJavaxServlet,
			})
			require.NoError(t, err)

			got, err := dbc.SelectIndexByArtifactIDAndGroupID(tt.artifactID, tt.groupID)
			tt.assertErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSelectIndexesByArtifactIDAndFileType(t *testing.T) {
	var tests = []struct {
		name        string
		artifactID  string
		archiveType types.ArchiveType
		want        []types.Index
	}{
		{
			name:        "happy path",
			artifactID:  "jstl",
			archiveType: types.JarType,
			want: []types.Index{
				indexJstl,
				indexJavaxServlet,
			},
		},
		{
			name:        "wrong ArtifactID",
			artifactID:  "wrong",
			archiveType: types.JarType,
			want:        []types.Index{},
		},
		{
			name:        "wrong Type",
			artifactID:  "jstl",
			archiveType: "wrong",
			want:        []types.Index{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbc, err := dbtest.InitDB(t, []*types.Index{
				&indexJstl,
				&indexJavaxServlet,
			})
			require.NoError(t, err)

			got, err := dbc.SelectIndexesByArtifactIDAndFileType(tt.artifactID, tt.archiveType)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
