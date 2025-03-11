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
	Versions []types.Version
}

type pomXML struct {
	Licenses []pomLicense `xml:"licenses>license"`
}

type pomLicense struct {
	Name string `xml:"name"`
}
