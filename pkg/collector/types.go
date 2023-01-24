package collector

type Metadata struct {
	GroupID    string     `xml:"groupId"`
	ArtifactID string     `xml:"artifactId"`
	Versioning Versioning `xml:"versioning"`
}

type Versioning struct {
	//Latest      string   `xml:"latest"`
	//Release     string   `xml:"release"`
	Versions    Versions `xml:"versions"`
	LastUpdated string   `xml:"lastUpdated"`
}

type Versions struct {
	Version []string `xml:"version"`
}
