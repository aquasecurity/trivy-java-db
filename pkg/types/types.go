package types

type ArchiveType string

const (
	// types of files
	JarType = "jar"
	AarType = "aar"
)

type Index struct {
	GroupID     string
	ArtifactID  string
	Version     string
	Sha1        []byte
	ArchiveType ArchiveType
}
