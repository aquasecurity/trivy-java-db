package db

import (
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var (
	indexJstl         = types.Index{GroupID: "jstl", ArtifactID: "jstl", Version: "1.0", Sha1: "9c581de633e94be1e7a955bd4e8292f16e554387", Type: types.JarType}
	indexJavaxServlet = types.Index{GroupID: "javax.servlet", ArtifactID: "jstl", Version: "1.1.0", Sha1: "bca201e52333629c59e459e874e5ecd8f9899e15", Type: types.JarType}
)

func initDB() error {
	tempDir, err := os.MkdirTemp("", "select-test")
	if err != nil {
		return err
	}
	err = Init(tempDir)
	if err != nil {
		return err
	}
	InsertIndex([]*types.Index{&indexJstl, &indexJavaxServlet})
	return nil
}

func TestSelectIndexBySha1(t *testing.T) {
	tests := []struct {
		name string
		sha1 string
		want types.Index
	}{
		{
			name: "happy path",
			sha1: "9c581de633e94be1e7a955bd4e8292f16e554387",
			want: indexJstl,
		},
		{
			name: "wrong sha1",
			sha1: "wrong",
			want: types.Index{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := initDB()
			assert.NoError(t, err)

			got := SelectIndexBySha1(tt.sha1)
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
	}{
		{
			name:       "happy path",
			groupID:    "javax.servlet",
			artifactID: "jstl",
			want:       indexJavaxServlet,
		},
		{
			name:       "wrong ArtifactID",
			groupID:    "javax.servlet",
			artifactID: "wrong",
			want:       types.Index{},
		},
		{
			name:       "wrong GroupID",
			groupID:    "wrong",
			artifactID: "jstl",
			want:       types.Index{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := initDB()
			assert.NoError(t, err)

			got := SelectIndexByArtifactIDAndGroupID(tt.artifactID, tt.groupID)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSelectIndexesByArtifactIDAndJarType(t *testing.T) {
	var tests = []struct {
		name       string
		artifactID string
		fileType   string
		want       []types.Index
	}{
		{
			name:       "happy path",
			artifactID: "jstl",
			fileType:   types.JarType,
			want:       []types.Index{indexJstl, indexJavaxServlet},
		},
		{
			name:       "wrong ArtifactID",
			artifactID: "wrong",
			fileType:   types.JarType,
			want:       []types.Index{},
		},
		{
			name:       "wrong Type",
			artifactID: "jstl",
			fileType:   "wrong",
			want:       []types.Index{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := initDB()
			assert.NoError(t, err)

			got := SelectIndexesByArtifactIDAndJarType(tt.artifactID, tt.fileType)
			assert.Equal(t, tt.want, got)
		})
	}
}
