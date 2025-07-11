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
	Classifier  string // TODO: This is not used yet, but we keep it for future use
	SHA1        []byte
	ArchiveType ArchiveType
}
