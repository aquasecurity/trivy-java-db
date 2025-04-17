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
	Versions  []types.Version   `json:"vs"`
	Packaging types.ArchiveType `json:"p"`
}

type GcsApiResponse struct {
	NextPageToken string `json:"nextPageToken,omitempty"`
	Items         []Item `json:"items,omitempty"`
}

type Item struct {
	Name string `json:"name"`
}
