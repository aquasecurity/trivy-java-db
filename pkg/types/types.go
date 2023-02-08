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
	Versions    []Version
	ArchiveType ArchiveType
}
type Version struct {
	Version string
	Sha1    []byte
}
