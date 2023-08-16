package db_test

import (
	"encoding/hex"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-java-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-java-db/pkg/types"

	_ "modernc.org/sqlite"
)

var (
	jstlSha1b, _         = hex.DecodeString("9c581de633e94be1e7a955bd4e8292f16e554387")
	javaxServletSha1b, _ = hex.DecodeString("bca201e52333629c59e459e874e5ecd8f9899e15")
	junitSHA, _          = hex.DecodeString("1013627e3993319870863a020034004717505815")
	indexJstl            = types.Index{
		GroupID:     "jstl",
		ArtifactID:  "jstl",
		Version:     "1.0",
		SHA1:        jstlSha1b,
		ArchiveType: types.JarType,
	}
	indexJavaxServlet = types.Index{
		GroupID:     "javax.servlet",
		ArtifactID:  "jstl",
		Version:     "1.1.0",
		SHA1:        javaxServletSha1b,
		ArchiveType: types.JarType,
	}
	indexJunit = types.Index{
		GroupID:     "junit",
		ArtifactID:  "junit",
		Version:     "4.9",
		SHA1:        junitSHA,
		ArchiveType: types.JarType,
		License:     "Common Public License Version 1.0",
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
		{
			name:      "index with license using sha",
			sha1:      "1013627e3993319870863a020034004717505815",
			want:      indexJunit,
			assertErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbc, err := dbtest.InitDB(t, []types.Index{
				indexJstl,
				indexJavaxServlet,
				indexJunit,
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
		{
			name:       "index with license using groupid and artifactid",
			groupID:    "junit",
			artifactID: "junit",
			want:       indexJunit,
			assertErr:  assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbc, err := dbtest.InitDB(t, []types.Index{
				indexJstl,
				indexJavaxServlet,
				indexJunit,
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
				indexJavaxServlet,
				indexJstl,
			},
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
		{
			name:        "index with license using artifactid and archivetype",
			artifactID:  "junit",
			archiveType: types.JarType,
			want: []types.Index{
				indexJunit,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbc, err := dbtest.InitDB(t, []types.Index{
				indexJstl,
				indexJavaxServlet,
				indexJunit,
			})
			require.NoError(t, err)

			got, err := dbc.SelectIndexesByArtifactIDAndFileType(tt.artifactID, tt.archiveType)
			sort.Slice(got, func(i, j int) bool {
				return got[i].GroupID < got[j].GroupID
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
