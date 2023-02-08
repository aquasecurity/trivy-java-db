package crawler

type Metadata struct {
	GroupID    string     `xml:"groupId"`
	ArtifactID string     `xml:"artifactId"`
	Versioning Versioning `xml:"versioning"`
}

type Versioning struct {
	//Latest      string   `xml:"latest"`
	//Release     string   `xml:"release"`
	Versions    []string `xml:"versions>version"`
	LastUpdated string   `xml:"lastUpdated"`
}

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
