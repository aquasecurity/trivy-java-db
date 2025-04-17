package types

type ArchiveType string

const (
	// types of files
	JarType = "jar"
	AarType = "aar"

	IndexesDir = "indexes"
)

type Index struct {
	GroupID     string
	ArtifactID  string
	Version     string
	SHA1        []byte
	ArchiveType ArchiveType
}

type Version struct {
	Version string `json:"v"`
	SHA1    string `json:"1"`
}
