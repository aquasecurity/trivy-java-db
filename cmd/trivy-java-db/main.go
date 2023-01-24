package main

import (
	"github.com/aquasecurity/trivy-java-db/pkg/collector"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
)

func main() {
	db.Init("/home/dmitriy/.cache/trivy-java")
	collector.CollectProjects()

}
