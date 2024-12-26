package db_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-java-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-java-db/pkg/types"

	_ "modernc.org/sqlite"
)

var (
	jstlSha1b, _            = hex.DecodeString("9c581de633e94be1e7a955bd4e8292f16e554387")
	javaxServlet10Sha1b, _  = hex.DecodeString("5d4ae7a8a17a33e01283e76e0dff66c4bce6456a")
	javaxServlet110Sha1b, _ = hex.DecodeString("bca201e52333629c59e459e874e5ecd8f9899e15")
	bundlesSha1b, _         = hex.DecodeString("b65e1196b26baeeec951fef2fefd4357")

	indexJstl = types.Index{
		GroupID:     "jstl",
		ArtifactID:  "jstl",
		Version:     "1.0",
		SHA1:        jstlSha1b,
		ArchiveType: types.JarType,
	}
	indexJavaxServlet10 = types.Index{
		GroupID:     "javax.servlet",
		ArtifactID:  "jstl",
		Version:     "1.0",
		SHA1:        javaxServlet10Sha1b,
		ArchiveType: types.JarType,
	}
	indexJavaxServlet11 = types.Index{
		GroupID:     "javax.servlet",
		ArtifactID:  "jstl",
		Version:     "1.1.0",
		SHA1:        javaxServlet110Sha1b,
		ArchiveType: types.JarType,
	}
	indexBundles = types.Index{
		GroupID:     "org.apache.geronimo.bundles",
		ArtifactID:  "jstl",
		Version:     "1.2_1",
		SHA1:        bundlesSha1b,
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
			sha1:      "1111111111111111111111111111111111111111",
			want:      types.Index{},
			assertErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbc, err := dbtest.InitDB(t, []types.Index{
				indexJstl,
				indexJavaxServlet10,
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
			want:       indexJavaxServlet10,
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
			dbc, err := dbtest.InitDB(t, []types.Index{
				indexJstl,
				indexJavaxServlet10,
			})
			require.NoError(t, err)

			got, err := dbc.SelectIndexByArtifactIDAndGroupID(tt.artifactID, tt.groupID)
			tt.assertErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSelectVersionsByArtifactIDAndGroupID(t *testing.T) {
	tests := []struct {
		name       string
		groupID    string
		artifactID string
		want       map[string][]byte
		assertErr  assert.ErrorAssertionFunc
	}{
		{
			name:       "happy path",
			groupID:    "javax.servlet",
			artifactID: "jstl",
			want: map[string][]byte{
				"1.0":   javaxServlet10Sha1b,
				"1.1.0": javaxServlet110Sha1b,
			},
			assertErr: assert.NoError,
		},
		{
			name:       "wrong ArtifactID",
			groupID:    "javax.servlet",
			artifactID: "wrong",
			want:       map[string][]byte{},
			assertErr:  assert.NoError,
		},
		{
			name:       "wrong GroupID",
			groupID:    "wrong",
			artifactID: "jstl",
			want:       map[string][]byte{},
			assertErr:  assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbc, err := dbtest.InitDB(t, []types.Index{
				indexJavaxServlet10,
				indexJavaxServlet11,
			})
			require.NoError(t, err)

			got, err := dbc.SelectVersionsByArtifactIDAndGroupID(tt.artifactID, tt.groupID)
			tt.assertErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSelectIndexesByArtifactIDAndFileType(t *testing.T) {
	var tests = []struct {
		name        string
		artifactID  string
		version     string
		archiveType types.ArchiveType
		wantIndexes []types.Index
	}{
		{
			name:        "happy path some indexes found",
			artifactID:  "jstl",
			version:     "1.0",
			archiveType: types.JarType,
			wantIndexes: []types.Index{
				indexJavaxServlet10,
				indexJavaxServlet11,
				indexJstl,
			},
		},
		{
			name:        "happy path one index found",
			artifactID:  "jstl",
			version:     "1.2_1",
			archiveType: types.JarType,
			wantIndexes: []types.Index{
				indexBundles,
			},
		},
		{
			name:        "there is no required version",
			artifactID:  "jstl",
			version:     "2.0",
			archiveType: types.JarType,
		},
		{
			name:        "wrong ArtifactID",
			artifactID:  "wrong",
			archiveType: types.JarType,
		},
		{
			name:        "wrong Type",
			artifactID:  "jstl",
			archiveType: "wrong",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbc, err := dbtest.InitDB(t, []types.Index{
				indexJstl,
				indexJavaxServlet10,
				indexJavaxServlet11,
				indexBundles,
			})
			require.NoError(t, err)

			gotIndexes, err := dbc.SelectIndexesByArtifactIDAndFileType(tt.artifactID, tt.version, tt.archiveType)

			require.NoError(t, err)
			assert.Equal(t, tt.wantIndexes, gotIndexes)
		})
	}
}
