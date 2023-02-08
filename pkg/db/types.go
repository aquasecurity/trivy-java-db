package db

import "github.com/aquasecurity/trivy-java-db/pkg/crawler"

type Index struct {
	GroupID     string
	ArtifactID  string
	Version     string
	Sha1        []byte
	ArchiveType crawler.ArchiveType
}
