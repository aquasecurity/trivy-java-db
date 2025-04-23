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

type GCSListResponse struct {
	NextPageToken string   `json:"nextPageToken,omitempty"`
	Items         []Item   `json:"items,omitempty"`
	Prefixes      []string `json:"prefixes,omitempty"`
}

type Item struct {
	Name string `json:"name"`
}

type Index struct {
	SHA1 string `json:"1"`
}
