package types

type ArchiveType string

const (
	// types of files
	JarType = "jar"
	AarType = "aar"

	IndexesDir                = "indexes"
	LicenseDir                = "licenses"
	NormalizedlicenseFileName = "/normalized_license.json"
)

type Index struct {
	GroupID     string
	ArtifactID  string
	Version     string
	SHA1        []byte
	ArchiveType ArchiveType
	License     string
}
