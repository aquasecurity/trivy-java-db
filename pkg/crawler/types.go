package crawler

import (
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

type Metadata struct {
	GroupID    string     `xml:"groupId"`
	ArtifactID string     `xml:"artifactId"`
	Versioning Versioning `xml:"versioning"`
}

type Versioning struct {
	Versions    []string `xml:"versions>version"`
	LastUpdated string   `xml:"lastUpdated"`
}

type Index struct {
	GroupID     string
	ArtifactID  string
	Versions    []types.Version
	ArchiveType types.ArchiveType
}
