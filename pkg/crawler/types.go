package crawler

import "github.com/aquasecurity/trivy-java-db/pkg/types"

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

type Index struct {
	GroupID     string
	ArtifactID  string
	Versions    []Version
	ArchiveType types.ArchiveType
}
type Version struct {
	Version string
	SHA1    []byte
	License string
}

type PomProject struct {
	GroupID     string    `xml:"groupId"`
	ArtifactID  string    `xml:"artifactId"`
	Version     string    `xml:"version"`
	Name        string    `xml:"name"`
	Description string    `xml:"description"`
	URL         string    `xml:"url"`
	Licenses    []License `xml:"licenses>license"`
}

type License struct {
	Name              string `xml:"name"`
	URL               string `xml:"url"`
	NormalizedLicense string
	LicenseKey        string
}
